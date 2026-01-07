// Copyright (c) 2023, Grant Hernandez
// SPDX-License-Identifier: MIT
package de.hernan.memory;

import java.util.ArrayList;
import java.io.IOException;

import javax.lang.model.util.ElementScanner14;

import ghidra.app.util.bin.BinaryReader;

public class MMUEntry extends MemEntry {
  /* Different firmwares may use different formats to calculate the end of the section in their MMU tables.
    * Example Oriole:  NUM_SECTIONS | PHYS_ADDRESS | VIRT_ADDRESS | FLAGS
    * Example Frankel: PHYS_ADDRESS | VIRT_ADDRESS | VIRT_END_ADDRESS | FLAGS
    * Below enum helps to differentiate MMUEntry Objectsbetween these formats.
    */
  public enum SectionEndFormat {
    NONE,
    END_ADDRESS,
    SECTION_COUNT,
  }

  private long phys_base;
  private SectionEndFormat format;
  private static int static_slotId = 0x0;



  private static String [] apName = new String[] {"NA","P_RW", "P_RW/U_RO", "RW", "RESV", "P_RO/U_NA", "RO_DEPR", "RO"};

  public MMUEntry(BinaryReader reader, SectionEndFormat format) throws IOException {
    this.format = format;
    if (format == SectionEndFormat.SECTION_COUNT) {
      readEntryWithSectionCount(reader);
    } else if (format == SectionEndFormat.END_ADDRESS) {
      readEntryWithEndAddress(reader);
    } else {
      throw new IOException("MMUEntry: Unknown SectionEndFormat");
    }
  }
  
  private void readEntryWithSectionCount(BinaryReader reader) throws IOException
  {
    long n_sections = reader.readNextUnsignedInt();
    this.phys_base = reader.readNextUnsignedInt();
    this.start = reader.readNextUnsignedInt();
    this.end = this.start + n_sections * 0x100000 - 1;
    this.flags = reader.readNextInt();
    this.size = (int)(this.end - this.start) + 1;
    this.slotId = static_slotId;
    static_slotId += 1;
  }

  private void readEntryWithEndAddress(BinaryReader reader) throws IOException
  {
    this.phys_base = reader.readNextUnsignedInt();
    this.start = reader.readNextUnsignedInt();
    this.end = reader.readNextUnsignedInt() - 1;
    this.flags = reader.readNextInt();
    this.size = (int)(this.end - this.start) + 1;
    this.slotId = static_slotId;
    static_slotId += 1;
  }

  public long getPhysBase() {
    return this.phys_base;
  }



  /* We are parsing the MMU Section table. According the to the ARMv7-A/R Architecture Reference Manual
   *  this looks something like this:
   31                                                      20 19 18 17 16 15 14 13 12 11 10  9  8 7 6 5  4  3  2  1  0
+------------------------------------------------------------+--+--+--+--+--+--------+-----+--+--------+--+--+--+--+--+
|                   Section base address, PA[31:20]          |NS|0 |nG| S|  |TEX[2:0]|     |  | Domain |XN| C| B|1 |  |
+------------------------------------------------------------+--+--+--+--+--+--------+-----+--+--------+--+--+--+--+--+
                                                                          |             |    |                       |
                                                                          |             |    |                      PXN                                                            |     |     |    |            |                      +-- PXN†
                                                                          |             |    +-- Implementation Defined           
                                                                        AP[2]         AP[1:0]   
   * Source: ARM DDI 0406C.d (ID040418)
   */


  @Override
  public boolean isExecutable() {
    // eXecute Never = 0 -> executable
    boolean user_is_executable = ( ((flags >> 4) & 1) == 0 );
    boolean priv_is_executable = (flags & 1) == 0;
    return user_is_executable || priv_is_executable;
  }

  public int getAPBits() {
    return ( ((flags >> 13) & 0b100) | (flags >> 10) & 0b11);
  }

  // we assume from perspective of supervisor
  @Override
  public boolean isReadable() {
    int bits = getAPBits();
    return bits != 0 && bits != 4;
  }

  @Override
  public boolean isWritable() {
    int bits = getAPBits();
    return bits == 1 || bits == 2 || bits == 3;
  }

  @Override
  public String toString() {
    return String.format("MMUEntry<start=%08x, end=%08x, exec=%s, ap=%s, slot=%d>",
        this.start, this.end, isExecutable(), apName[getAPBits()], getSlotId());
  }
}
