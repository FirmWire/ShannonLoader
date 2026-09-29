// Copyright (c) 2023, Grant Hernandez
// SPDX-License-Identifier: MIT
package de.hernan;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import ghidra.app.util.bin.ByteProvider;
import ghidra.util.Msg;

/* Splits the BOOT TOC section into the independently linked images it contains.
 *
 * Up to and including the Exynos Modem 5123 (e.g. Pixel 6 "oriole", G991B) the BOOT
 * section is a single flat bootloader: its first bytes ARE the ARM exception vector
 * table, the image is linked at the TOC load address and VBAR is left at its reset
 * value. Nothing needs to be recovered, so this class hands such images straight
 * back as one BootImage and the load behaves exactly as it always has.
 *
 * Newer parts (Exynos Modem 5300/5400, i.e. Pixel 7 and later, S25) turned BOOT into
 * a signed container. Its first bytes are a header carrying a chip id ("S5400"),
 * vendor records and ECDSA material, so no vector table is visible at offset 0.
 * The bootloader proper ("STBL") sits deep inside the container and is no longer
 * linked at 0 either, and on 5400-class images a small first stage is placed ahead
 * of it. For the Pixel 10 (g5400i) the layout is:
 *
 *   BOOT+0x0000  container header: {0x8, crc, 0, 0}, "S5400", P-521 signature
 *   BOOT+0x1000  first stage, header {b entry, 0, size, 0x54000200}, linked at 0x00000000
 *   BOOT+0xb000  small stub, same header shape, no recoverable link address
 *   BOOT+0xb410  STBL bootloader, linked at 0x02019800
 *   BOOT+0x219f0 trailing signature
 *
 * Load addresses are never hardcoded here. Every relocated image programs VBAR in
 * its reset handler, so the runtime address of its vector table is spelled out in
 * the image itself:
 *
 *     ldr rX, [pc, #imm]                 ; rX = vector base
 *     mcr p15, 0, rX, c12, c0, 0         ; VBAR = rX
 *
 * Recovering that literal gives the address of the vector table, and the distance
 * from the image start to its vector table gives the image load address.
 */
public class BootContainer
{
    private static final int ARM_INSN_SIZE = 4;
    private static final int ARM_VECTOR_TABLE_ENTRIES = 8;
    private static final int ARM_VECTOR_TABLE_SIZE = ARM_VECTOR_TABLE_ENTRIES * ARM_INSN_SIZE;

    // b .  -- the architecturally reserved vector slot parks on itself in every
    // Shannon bootloader seen so far, which makes it a cheap discriminator
    private static final int ARM_BRANCH_SELF = 0xeafffffe;

    // b <target>
    private static final int ARM_BRANCH_MASK = 0xff000000;
    private static final int ARM_BRANCH = 0xea000000;

    // ldr rX, [pc, #imm12]
    private static final int ARM_LDR_PC_MASK = 0xffff0000;
    private static final int ARM_LDR_PC = 0xe59f0000;

    // mcr p15, 0, rX, c12, c0, 0 -- the Rt field (bits 15:12) is zeroed here
    private static final int ARM_MCR_VBAR = 0xee0c0f10;

    /* Header of a container sub-image: {b <entry>, 0, size, magic}. The size field is
     * advisory (it excludes trailing image metadata) so only the magic is relied on.
     */
    private static final int SUBIMAGE_MAGIC = 0x54000200;
    private static final int SUBIMAGE_HEADER_SIZE = 16;

    // "STBL" as a big-endian packed fourcc, found 0x30 bytes into the bootloader image
    private static final int STBL_MAGIC = 0x5354424c;
    private static final int STBL_MAGIC_OFFSET = 0x30;

    // Container records and sub-images are always 16 byte aligned
    private static final int CONTAINER_ALIGNMENT = 16;

    // How far into a reset handler we are willing to look for the VBAR write
    private static final int VBAR_SEARCH_LIMIT = 0x200;

    // Printable chip id of the container, when the header carries one
    private static final int CHIP_ID_OFFSET = 0x10;
    private static final int CHIP_ID_SIZE = 16;
    private static final int CHIP_ID_MIN_LENGTH = 4;

    private final byte[] data;
    private final int fileOffset;
    private final long tocLoadAddress;

    private class Candidate {
        final int start;
        final int size;
        final long loadAddress;
        final boolean bootloader;

        Candidate(int start, int size, long loadAddress, boolean bootloader) {
            this.start = start;
            this.size = size;
            this.loadAddress = loadAddress;
            this.bootloader = bootloader;
        }
    }

    public BootContainer(ByteProvider provider, TOCSectionHeader sec_boot) throws IOException
    {
        this.data = provider.readBytes(sec_boot.getOffset(), sec_boot.getSize());
        this.fileOffset = sec_boot.getOffset();
        this.tocLoadAddress = Integer.toUnsignedLong(sec_boot.getLoadAddress());
    }

    public List<BootImage> parse()
    {
        List<BootImage> flat = new ArrayList<>();
        flat.add(new BootImage("BOOT", fileOffset, data.length, tocLoadAddress));

        if (isVectorTable(0)) {
          Msg.info(this, "BOOT: flat bootloader (exception vector table at offset 0)");
          return flat;
        }

        Msg.info(this, "==== BOOT is a container, recovering sub-images ====");

        String chipId = readChipId();
        if (chipId != null)
          Msg.info(this, String.format("BOOT: container chip id '%s'", chipId));

        Map<Integer, Integer> declared = findDeclaredSubImages();
        List<Integer> vectorTables = findVectorTables();

        TreeSet<Integer> anchors = new TreeSet<>(declared.keySet());
        for (int vectorTable : vectorTables) {
          if (findDeclaringSubImage(declared, vectorTable) == -1)
            anchors.add(vectorTable);
        }

        if (anchors.isEmpty()) {
          Msg.warn(this, "BOOT: no sub-images recognized in container. Falling back to a flat load, which will place the container header at the BOOT load address.");
          return flat;
        }

        List<Candidate> candidates = new ArrayList<>();
        List<Integer> anchorList = new ArrayList<>(anchors);

        for (int i = 0; i < anchorList.size(); i++) {
          int anchor = anchorList.get(i);
          int regionEnd = (i + 1 < anchorList.size()) ? anchorList.get(i + 1) : data.length;

          Candidate candidate = describeSubImage(anchor, regionEnd,
              declared.containsKey(anchor), vectorTables);

          if (candidate != null)
            candidates.add(candidate);
        }

        if (candidates.isEmpty()) {
          Msg.warn(this, "BOOT: container recognized but no sub-image load address could be recovered. Falling back to a flat load.");
          return flat;
        }

        return nameCandidates(candidates);
    }

    /* The bootloader proper keeps the name "BOOT" so that downstream block naming
     * matches what legacy images produce. When no image carries the STBL magic the
     * largest one is the bootloader, the smaller ones being early boot stages.
     */
    private List<BootImage> nameCandidates(List<Candidate> candidates)
    {
        int bootloader = 0;

        for (int i = 0; i < candidates.size(); i++) {
          if (candidates.get(i).bootloader) {
            bootloader = i;
            break;
          }

          if (candidates.get(i).size > candidates.get(bootloader).size)
            bootloader = i;
        }

        List<BootImage> images = new ArrayList<>();
        int stage = 0;

        for (int i = 0; i < candidates.size(); i++) {
          Candidate candidate = candidates.get(i);
          String name = (i == bootloader) ? "BOOT" : String.format("BOOT_STAGE%d", ++stage);

          images.add(new BootImage(name, fileOffset + candidate.start,
                candidate.size, candidate.loadAddress));
        }

        return images;
    }

    private Candidate describeSubImage(int anchor, int regionEnd, boolean declared,
        List<Integer> vectorTables)
    {
        int vectorTable = firstVectorTableIn(vectorTables, anchor, regionEnd);
        int entry = branchTarget(anchor);

        if (vectorTable == -1 || entry == -1) {
          Msg.warn(this, String.format("BOOT: skipping [%08x - %08x], no %s",
                anchor, regionEnd, vectorTable == -1 ? "vector table" : "entry branch"));
          return null;
        }

        long vectorBase = findVbarWrite(entry);

        if (vectorBase == -1) {
          Msg.warn(this, String.format("BOOT: skipping [%08x - %08x], reset handler at %08x does not program VBAR so its load address is unknown",
                anchor, regionEnd, entry));
          return null;
        }

        /* A declared sub-image starts at its header. Otherwise the anchor is the vector
         * table itself and the image may still extend below it, as far down as the reset
         * handler the table branches to.
         */
        int start = declared ? anchor : Math.min(anchor, alignDown(entry));
        long loadAddress = vectorBase - (vectorTable - start);

        int size = trimTrailingZeros(start, regionEnd);

        if (size == 0) {
          Msg.warn(this, String.format("BOOT: skipping empty region [%08x - %08x]", anchor, regionEnd));
          return null;
        }

        boolean bootloader = readInt(vectorTable + STBL_MAGIC_OFFSET) == STBL_MAGIC;

        Msg.info(this, String.format("BOOT: sub-image [%08x - %08x] loads at %08x (vector table at +%04x, VBAR %08x)%s",
              start, start + size, loadAddress, vectorTable - start, vectorBase,
              bootloader ? " [STBL]" : ""));

        return new Candidate(start, size, loadAddress, bootloader);
    }

    private Map<Integer, Integer> findDeclaredSubImages()
    {
        Map<Integer, Integer> declared = new LinkedHashMap<>();

        for (int offset = 0; offset + SUBIMAGE_HEADER_SIZE <= data.length; offset += CONTAINER_ALIGNMENT) {
          // require the whole header shape, the magic alone hits often enough in data
          if (readInt(offset + 12) != SUBIMAGE_MAGIC)
            continue;
          if (!isBranch(readInt(offset)) || readInt(offset + 4) != 0)
            continue;

          declared.put(offset, readInt(offset + 8));
        }

        return declared;
    }

    private List<Integer> findVectorTables()
    {
        List<Integer> tables = new ArrayList<>();

        for (int offset = 0; offset + ARM_VECTOR_TABLE_SIZE <= data.length; offset += CONTAINER_ALIGNMENT) {
          if (isVectorTable(offset))
            tables.add(offset);
        }

        return tables;
    }

    private int findDeclaringSubImage(Map<Integer, Integer> declared, int offset)
    {
        for (Map.Entry<Integer, Integer> entry : declared.entrySet()) {
          int start = entry.getKey();
          int end = start + Math.max(entry.getValue(), SUBIMAGE_HEADER_SIZE);

          if (offset >= start && offset < end)
            return start;
        }

        return -1;
    }

    private int firstVectorTableIn(List<Integer> vectorTables, int start, int end)
    {
        for (int vectorTable : vectorTables) {
          if (vectorTable >= start && vectorTable < end)
            return vectorTable;
        }

        return -1;
    }

    private boolean isVectorTable(int offset)
    {
        if (!inBounds(offset, ARM_VECTOR_TABLE_SIZE))
          return false;

        if (readInt(offset + 5 * ARM_INSN_SIZE) != ARM_BRANCH_SELF)
          return false;

        for (int i = 0; i < ARM_VECTOR_TABLE_ENTRIES; i++) {
          int insn = readInt(offset + i * ARM_INSN_SIZE);

          if (!isBranch(insn) && !isLoadPC(insn))
            return false;
        }

        return true;
    }

    private int branchTarget(int offset)
    {
        int insn = readInt(offset);

        if (!isBranch(insn))
          return -1;

        // sign extend imm24 and scale it by the instruction size in one shift pair
        int target = offset + 8 + ((insn << 8) >> 6);

        return inBounds(target, ARM_INSN_SIZE) ? target : -1;
    }

    private long findVbarWrite(int offset)
    {
        for (int scan = 0; scan < VBAR_SEARCH_LIMIT; scan += ARM_INSN_SIZE) {
          int at = offset + scan;

          if (!inBounds(at, 2 * ARM_INSN_SIZE))
            break;

          int load = readInt(at);

          if (!isLoadPC(load))
            continue;

          int reg = (load >> 12) & 0xf;

          if (readInt(at + ARM_INSN_SIZE) != (ARM_MCR_VBAR | (reg << 12)))
            continue;

          int literal = at + 8 + (load & 0xfff);

          if (!inBounds(literal, ARM_INSN_SIZE))
            return -1;

          return Integer.toUnsignedLong(readInt(literal));
        }

        return -1;
    }

    /* The gap between two sub-images is zero padding. Dropping it keeps a relocated
     * image from running into whatever is mapped after it (APM sits close behind the
     * bootloader on 5400-class parts).
     */
    private int trimTrailingZeros(int start, int end)
    {
        int last = end;

        while (last > start && data[last - 1] == 0)
          last--;

        if (last == start)
          return 0;

        return Math.min(align(last - start), end - start);
    }

    private String readChipId()
    {
        if (!inBounds(CHIP_ID_OFFSET, CHIP_ID_SIZE))
          return null;

        StringBuilder id = new StringBuilder();

        for (int i = 0; i < CHIP_ID_SIZE; i++) {
          int c = data[CHIP_ID_OFFSET + i] & 0xff;

          if (c == 0)
            break;
          if (c < 0x20 || c > 0x7e)
            return null;

          id.append((char)c);
        }

        if (id.length() < CHIP_ID_MIN_LENGTH)
          return null;

        // anything after the string must be padding for this to be an identifier field
        for (int i = id.length(); i < CHIP_ID_SIZE; i++) {
          if (data[CHIP_ID_OFFSET + i] != 0)
            return null;
        }

        return id.toString();
    }

    private boolean isBranch(int insn)
    {
        return (insn & ARM_BRANCH_MASK) == ARM_BRANCH;
    }

    private boolean isLoadPC(int insn)
    {
        return (insn & ARM_LDR_PC_MASK) == ARM_LDR_PC;
    }

    private int align(int value)
    {
        return (value + CONTAINER_ALIGNMENT - 1) & ~(CONTAINER_ALIGNMENT - 1);
    }

    private int alignDown(int value)
    {
        return value & ~(CONTAINER_ALIGNMENT - 1);
    }

    private boolean inBounds(int offset, int length)
    {
        return offset >= 0 && length >= 0 && offset <= data.length - length;
    }

    private int readInt(int offset)
    {
        if (!inBounds(offset, ARM_INSN_SIZE))
          return 0;

        return (data[offset] & 0xff)
            | ((data[offset + 1] & 0xff) << 8)
            | ((data[offset + 2] & 0xff) << 16)
            | ((data[offset + 3] & 0xff) << 24);
    }
}
