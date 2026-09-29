// Copyright (c) 2023, Grant Hernandez
// SPDX-License-Identifier: MIT
package de.hernan;

/* One independently linked image found inside the BOOT TOC section.
 *
 * Legacy BOOT sections hold exactly one of these covering the whole section.
 * Container style BOOT sections (see BootContainer) hold several, each with its
 * own load address that has nothing to do with the BOOT TOC load address.
 */
public class BootImage
{
    private final String name;
    private final int fileOffset;
    private final int size;
    private final long loadAddress;

    public BootImage(String name, int fileOffset, int size, long loadAddress)
    {
        this.name = name;
        this.fileOffset = fileOffset;
        this.size = size;
        this.loadAddress = loadAddress;
    }

    public String getName()
    {
        return this.name;
    }

    public int getFileOffset()
    {
        return this.fileOffset;
    }

    public int getSize()
    {
        return this.size;
    }

    public long getLoadAddress()
    {
        return this.loadAddress;
    }

    @Override
    public String toString()
    {
      return String.format("BootImage<name=%s, offset=%08x, size=%08x, loadAddress=%08x>",
          this.name, this.fileOffset, this.size, this.loadAddress);
    }
}
