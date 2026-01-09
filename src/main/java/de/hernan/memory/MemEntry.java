package de.hernan.memory;


public class MemEntry {
    protected long start;
    protected long end;
    protected int size;
    protected int flags;
    protected int slotId;

    public long getStartAddress() {
        return this.start;
    }

    public long getEndAddress() {
        return this.end;
    }

    public long getSize() {
        return this.size;
    }


    /* Only MPUEntries really have slotIDs. However, slotIds are used to resolve
     * overlapping memory regions. By assigning increasing slotIDs to MMUEntries, we
     * can use the same logic for both MPU and MMU entries.
     */
    public int getSlotId() {
        return this.slotId;
    }

    /* Default permissions, if not overridden by subclass: RWX */
    public boolean isReadable() {
        return true;
    }

    public boolean isWritable() {
        return true;
    }

    public boolean isExecutable() {
        return true;
    }
}