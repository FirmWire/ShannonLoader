# Recovers the Shannon RTOS task list, its structures and its task entry points
# @author Must Bastani
# @category Shannon
## Copyright (c) 2026, Must Bastani
## SPDX-License-Identifier: MIT

from __future__ import print_function

import re

from ghidra.app.cmd.disassemble import ArmDisassembleCommand
from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import ArrayDataType
from ghidra.program.model.data import ByteDataType
from ghidra.program.model.data import CategoryPath
from ghidra.program.model.data import CharDataType
from ghidra.program.model.data import DataTypeConflictHandler
from ghidra.program.model.data import DefaultDataType
from ghidra.program.model.data import PointerDataType
from ghidra.program.model.data import Structure
from ghidra.program.model.data import StructureDataType
from ghidra.program.model.data import Undefined
from ghidra.program.model.data import UnsignedIntegerDataType
from ghidra.program.model.data import VoidDataType
from ghidra.program.model.listing import Function
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.symbol import SourceType

# Task layouts as recovered by FirmWire (firmwire/vendor/shannon/task.py). The
# SUBTASK_* offsets belong to the scheduler thread struct, not to Task: on
# CortexA a SubTask reaches 0x144 bytes and therefore cannot live inside the
# 0x240 byte Task.
SAMSUNG_CORTEX_R = {
    "name": "samsung-r",
    "task_size": 0x108,
    "task_stackbase": 0x10,
    "task_name_ptr": 0x24,
    "task_sched_prio": 0x28,
    "task_stacksize": 0x2C,
    "task_main_fn": 0x30,
    "task_pre_fn": 0x34,
    "subtask_magic": 0x08,
    "subtask_name": 0x5C,
    "subtask_name_size": 0x08,
    "subtask_task_p": 0x68,
}

SAMSUNG_CORTEX_A = {
    "name": "samsung-a",
    "task_size": 0x240,
    "task_stackbase": 0x10,
    "task_name_ptr": 0x24,
    "task_sched_prio": 0x28,
    "task_stacksize": 0x2C,
    "task_main_fn": 0x30,
    "task_pre_fn": 0x34,
    "subtask_magic": 0x08,
    "subtask_name": 0x24,
    "subtask_name_size": 0x08,
    "subtask_task_p": 0x140,
}

# FirmWire++ sizes this Task 0x1C8 while Pixel 7 (panther) builds use 0x1D8,
# hence the Task size search when no array of task_size exists. The SubTask
# offsets FirmWire++ gives are unverified and therefore left out.
SAMSUNG_S53XX = {
    "name": "samsung-s53xx",
    "task_size": 0x1D8,
    "task_stackbase": 0x10,
    "task_name_ptr": 0x4C,
    "task_sched_prio": 0x50,
    "task_stacksize": 0x54,
    "task_main_fn": 0x58,
    "task_pre_fn": 0x5C,
}

# Task size as in Pixel 10 (frankel) builds and FirmWire++
SAMSUNG_S54XX = dict(SAMSUNG_S53XX, name="samsung-s54xx", task_size=0x1F8)

TASK_LAYOUTS = [SAMSUNG_CORTEX_A, SAMSUNG_S53XX, SAMSUNG_S54XX, SAMSUNG_CORTEX_R]

# SoCs shipping a Cortex-R modem core are 4G only, Cortex-A ones carry 5G
SOC_LAYOUT = {
    "S335AP": SAMSUNG_CORTEX_R,
    "S337AP": SAMSUNG_CORTEX_R,
    "S353AP": SAMSUNG_CORTEX_R,
    "S355AP": SAMSUNG_CORTEX_R,
    "S360AP": SAMSUNG_CORTEX_R,
    "S5000AP": SAMSUNG_CORTEX_R,
    "S5123": SAMSUNG_CORTEX_A,
    "S5123AP": SAMSUNG_CORTEX_A,
    "S5300": SAMSUNG_S53XX,
    "S5400": SAMSUNG_S54XX,
}

# Task names that every Shannon image seen so far schedules
ANCHOR_TASK_NAMES = ["GLAPD", "PDNMGR", "SAEL3", "MSD_OT"]

# Pixel builds name the SoC only in their version string, as in
# g5300q-260604-260807-B-16036236. Other builds carry the SoC-ID, some junk
# and a YYYYMMDD date, the version string ShannonLoader.java looks for.
SOC_VERSION_PATTERN = "g[0-9]{4}[a-z]?-[0-9]{6}-[0-9]{6}-|S[0-9]{3,4}(AP)?.{0,10}[0-9]{8}"
PIXEL_VERSION = re.compile(r"^g([0-9]{4})[a-z]?-")
SOC_VERSION = re.compile(r"^(S[0-9]{3,4}(AP)?)(?![0-9]).{0,10}[0-9]{8}", re.S)
# Builds with neither, as S21 ones, still name the SoC in strings such as
# S5123AP_PROD_SMP1600T1_PALETTE_SA_211007_174936
SOC_ID_PATTERN = "S[0-9]{3,4}(AP)?"
SOC_ID = re.compile(r"^(S[0-9]{3,4}(AP)?)(?![0-9])")
IDENTIFIER_CHAR = re.compile(r"[A-Za-z0-9_]")
SOC_SEARCH_CHUNK = 0x800000
SOC_SEARCH_PAGE = 64

TASK_NAME = re.compile(r"^[A-Za-z0-9_]{2,24}$")
TASK_NAME_MAX = 32

# A candidate array has to hold at least this many tasks to be believable
MIN_TASKS = 16
MAX_TASKS = 4096
# Every known Task embeds its thread control block, the smallest is 0x108 bytes
MIN_TASK_SIZE = 0x100
MAX_TASK_SIZE = 0x400
MAX_STACK_SIZE = 0x100000

# Change to false if you don't want your output window to be spammed
SHOW_OUTPUT = True


def read_u32(addr):
    try:
        return getInt(addr) & 0xFFFFFFFF
    except Exception:
        return None


# Not toAddr(): PyGhidra resolves it to toAddr(int), which rejects offsets
# from 0x80000000 up
def to_addr(value):
    try:
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value)
    except Exception:
        return None


def is_initialized(addr):
    if addr is None:
        return False
    block = currentProgram.getMemory().getBlock(addr)
    return block is not None and block.isInitialized()


def read_cstring(addr, max_len):
    out = []
    for i in range(max_len):
        try:
            byte = getByte(addr.add(i)) & 0xFF
        except Exception:
            return None
        if byte == 0:
            return "".join(out)
        out.append(chr(byte))
    return None


def read_ascii(addr, max_len):
    """Everything printable at `addr', however the run ends"""
    out = []
    for i in range(max_len):
        try:
            byte = getByte(addr.add(i)) & 0xFF
        except Exception:
            break
        if byte < 0x20 or byte > 0x7E:
            break
        out.append(chr(byte))
    return "".join(out)


def read_bytes(addr, max_len):
    out = []
    for i in range(max_len):
        try:
            out.append(chr(getByte(addr.add(i)) & 0xFF))
        except Exception:
            break
    return "".join(out)


def follows_identifier(addr):
    try:
        previous = chr(getByte(addr.subtract(1)) & 0xFF)
    except Exception:
        return False
    return IDENTIFIER_CHAR.match(previous) is not None


def search_chunks():
    """Initialized memory in ascending address order, in searchable slices"""
    for block in currentProgram.getMemory().getBlocks():
        if not block.isInitialized():
            continue
        start = block.getStart()
        size = block.getSize()
        for offset in range(0, size, SOC_SEARCH_CHUNK):
            last = min(offset + SOC_SEARCH_CHUNK, size) - 1
            yield AddressSet(start.add(offset), start.add(last))


def search_hits(pattern):
    """Every match of `pattern' in initialized memory, in ascending address order"""
    for chunk in search_chunks():
        while not chunk.isEmpty():
            if monitor.isCancelled():
                return
            hits = findBytes(chunk, pattern, SOC_SEARCH_PAGE, 1)
            for hit in hits:
                yield hit
            if len(hits) < SOC_SEARCH_PAGE:
                break
            chunk = chunk.subtract(AddressSet(chunk.getMinAddress(), hits[len(hits) - 1]))


def soc_of_version(text):
    pixel = PIXEL_VERSION.match(text)
    if pixel is not None:
        return "S" + pixel.group(1)
    match = SOC_VERSION.match(text)
    return None if match is None else match.group(1)


def known_soc_id(text):
    """Bare SoC-IDs also name RF chips such as S5511, so only SoCs of a known
    task layout count"""
    match = SOC_ID.match(text)
    if match is None or match.group(1) not in SOC_LAYOUT:
        return None
    return match.group(1)


def search_soc(pattern, parse):
    for hit in search_hits(pattern):
        if follows_identifier(hit):
            continue
        soc = parse(read_bytes(hit, 64))
        if soc is not None:
            return soc, read_ascii(hit, 64)
    return None, None


def find_soc():
    """Returns the SoC-ID and the text naming it

    A version string names any SoC. Failing that, the first bare SoC-ID of a
    known task layout is taken.
    """
    monitor.setMessage("Searching for the SoC version string...")
    soc, text = search_soc(SOC_VERSION_PATTERN, soc_of_version)
    if soc is not None:
        return soc, text

    monitor.setMessage("Searching for a SoC-ID...")
    return search_soc(SOC_ID_PATTERN, known_soc_id)


def layout_preference(preferred):
    if preferred is None:
        return list(TASK_LAYOUTS)
    return [preferred] + [other for other in TASK_LAYOUTS if other is not preferred]


def task_name_of(task, layout):
    name_ptr = read_u32(task.add(layout["task_name_ptr"]))
    if not name_ptr:
        return None
    name_addr = to_addr(name_ptr)
    if not is_initialized(name_addr):
        return None
    name = read_cstring(name_addr, TASK_NAME_MAX)
    if name is None or TASK_NAME.match(name) is None:
        return None
    return name


def is_task(task, layout):
    # Rules out tables of string pointers, which pass every other check at any stride
    stacksize = read_u32(task.add(layout["task_stacksize"]))
    if not stacksize or stacksize > MAX_STACK_SIZE:
        return False
    if task_name_of(task, layout) is None:
        return False
    main_fn = read_u32(task.add(layout["task_main_fn"]))
    if not main_fn:
        return False
    return is_initialized(to_addr(main_fn & ~1))


def measure_array(anchor, layout, stride):
    """Grows an array of `stride' byte tasks around `anchor', a Task base address"""
    start = anchor
    while start.getOffset() > stride:
        previous = start.subtract(stride)
        if not is_task(previous, layout):
            break
        start = previous

    count = 0
    while count < MAX_TASKS and is_task(start.add(count * stride), layout):
        count += 1

    return start, count


def stack_bases(start, count, layout, stride):
    return len([index for index in range(count)
                if read_u32(start.add(index * stride + layout["task_stackbase"]))])


def anchor_candidates():
    """Addresses that may hold the name pointer of a well known task"""
    base = currentProgram.getMinAddress()

    for anchor in ANCHOR_TASK_NAMES:
        monitor.setMessage("Searching for task name '%s'..." % anchor)

        # No leading NUL: the linker merges a name into the tail of a longer
        # string, as SAEL3 into DS_SAEL3
        for name_addr in findBytes(base, "%s\\x00" % anchor, 8, 1):
            pattern = "".join(
                ["\\x%02x" % ((name_addr.getOffset() >> shift) & 0xFF) for shift in (0, 8, 16, 24)])

            monitor.setMessage("Searching for references to '%s'..." % anchor)

            for xref in findBytes(base, pattern, 8, 4):
                yield xref

        if monitor.isCancelled():
            return


def anchor_tasks(layouts):
    """(layout, Task base address) pairs of well known tasks, in layout preference order"""
    for xref in anchor_candidates():
        if monitor.isCancelled():
            return
        for layout in layouts:
            base = xref.subtract(layout["task_name_ptr"])
            if is_task(base, layout):
                yield layout, base


def find_sized_task_list(layouts):
    best = (None, None, None, 0)

    for layout, base in anchor_tasks(layouts):
        stride = layout["task_size"]
        start, count = measure_array(base, layout, stride)
        if count > best[3]:
            best = (layout, stride, start, count)
        if count >= MIN_TASKS:
            break

    return best


def find_longest_task_list(layouts):
    """Some stride lines up the records of unrelated tables too, so only the
    longest array any anchor yields is trusted

    A layout whose fields sit at a constant distance from another layout's
    matches that layout's tasks just as long at a shifted base. Only the
    right one finds stack bases, so they break the tie.
    """
    best = (None, None, None, 0)
    best_stacks = 0

    for layout, base in anchor_tasks(layouts):
        for stride in range(MIN_TASK_SIZE, MAX_TASK_SIZE + 1, 4):
            start, count = measure_array(base, layout, stride)
            if count == 0 or count < best[3]:
                continue
            stacks = stack_bases(start, count, layout, stride)
            if count > best[3] or stacks > best_stacks:
                best = (layout, stride, start, count)
                best_stacks = stacks

    return best


def find_task_list(layouts):
    """Returns (layout, stride, array start, task count) of the best candidate found"""
    best = find_sized_task_list(layouts)
    if best[3] >= MIN_TASKS:
        return best

    print("WARNING: no task list with a known Task size, searching for the Task size")
    return find_longest_task_list(layouts)


def find_struct(name):
    for dt in getDataTypes(name):
        if isinstance(dt, Structure):
            return dt
    return None


def is_defined(struct, offset):
    component = struct.getComponentContaining(offset)
    if component is None:
        return False
    dt = component.getDataType()
    return not (Undefined.isUndefined(dt) or isinstance(dt, DefaultDataType))


def ensure_struct(name, size, fields, fixed_size):
    """Creates `name', or fills in the fields an existing definition is missing

    An existing definition is never resized: other types may embed it. That is
    fatal for Task, whose size is the stride of the task list array.
    """
    dtm = currentProgram.getDataTypeManager()
    struct = find_struct(name)

    if struct is None:
        struct = dtm.addDataType(
            StructureDataType(CategoryPath.ROOT, name, size),
            DataTypeConflictHandler.DEFAULT_HANDLER)
        print("Created %s (0x%x bytes)" % (name, size))
    elif struct.getLength() != size:
        if fixed_size:
            print("ERROR: existing %s is 0x%x bytes but the task layout needs 0x%x. "
                  "Rename or delete it and re-run." % (name, struct.getLength(), size))
            return None
        print("Keeping the existing %s (0x%x bytes, the task layout describes 0x%x)" %
              (name, struct.getLength(), size))
    else:
        print("Reusing the existing %s definition" % name)

    for offset, dt, field in fields:
        if offset + dt.getLength() > struct.getLength():
            print("  %s +0x%03x %s does not fit, skipped" % (name, offset, field))
            continue
        if is_defined(struct, offset):
            continue
        struct.replaceAtOffset(offset, dt, dt.getLength(), field, None)
        print("  %s +0x%03x %s %s" % (name, offset, dt.getName(), field))

    return struct


def create_types(layout, task_size):
    dtm = currentProgram.getDataTypeManager()
    uint = UnsignedIntegerDataType.dataType
    size = currentProgram.getDefaultPointerSize()
    pointer = PointerDataType.getPointer(None, dtm)

    task = ensure_struct("Task", task_size, [
        (layout["task_stackbase"], pointer, "stackbase"),
        (layout["task_name_ptr"], PointerDataType.getPointer(CharDataType.dataType, dtm), "name"),
        (layout["task_sched_prio"], ByteDataType.dataType, "sched_prio"),
        (layout["task_stacksize"], uint, "stacksize"),
        (layout["task_main_fn"], pointer, "main"),
        (layout["task_pre_fn"], pointer, "pre_main"),
    ], True)

    if task is None or "subtask_task_p" not in layout:
        return task

    name_size = layout["subtask_name_size"]
    ensure_struct("SubTask", layout["subtask_task_p"] + size, [
        (layout["subtask_magic"], uint, "magic"),
        (layout["subtask_name"], ArrayDataType(CharDataType.dataType, name_size, 1), "name"),
        (layout["subtask_task_p"], PointerDataType.getPointer(task, dtm), "task"),
    ], False)

    return task


def label_task_list(start, count, task):
    """Types the whole array in one go so no stale code unit can split it"""
    end = start.add(count * task.getLength() - 1)

    try:
        clearListing(start, end)
        createData(start, ArrayDataType(task, count, task.getLength()))
    except Exception as e:
        print("ERROR: cannot lay out Task[%d] over %s - %s: %s" % (count, start, end, e))
        return False

    for symbol in currentProgram.getSymbolTable().getGlobalSymbols("TaskListArray"):
        if not symbol.getAddress().equals(start):
            print("Removing stale TaskListArray label at %s" % symbol.getAddress())
            symbol.delete()

    createLabel(start, "TaskListArray", True, SourceType.USER_DEFINED)
    print("TaskListArray: Task[%d] at %s - %s" % (count, start, end))
    return True


def define_task_name(addr, name):
    """Types the task name unless a string already ends with it, taking the
    bytes back from any other overlapping data"""
    data = getDataContaining(addr)
    if data is not None and data.hasStringValue() and data.getMaxAddress().equals(addr.add(len(name))):
        return False

    try:
        clearListing(addr, addr.add(len(name)))
        createAsciiString(addr)
    except Exception as e:
        print("ERROR: cannot create the name string of %s at %s: %s" % (name, addr, e))
        return False

    return True


def is_thumb(addr):
    context = currentProgram.getProgramContext()
    tmode = context.getRegister("TMode")
    if tmode is None:
        return None
    value = context.getRegisterValue(tmode, addr)
    if value is None or not value.hasValue():
        return None
    return value.getUnsignedValue().intValue() == 1


def disassemble_entry(entry, thumb):
    instruction = getInstructionAt(entry)
    if instruction is not None and is_thumb(entry) == thumb:
        return True

    if instruction is not None or getDataAt(entry) is not None:
        clearListing(entry, entry.add(3))

    return ArmDisassembleCommand(entry, None, thumb).applyTo(currentProgram, monitor)


def rename(function, name, taken):
    """Names `function' `name', keeping the name unique across the task list"""
    if taken.get(name, function.getEntryPoint()).equals(function.getEntryPoint()):
        taken[name] = function.getEntryPoint()
    else:
        suffix = 1
        while "%s_%d" % (name, suffix) in taken:
            suffix += 1
        name = "%s_%d" % (name, suffix)
        taken[name] = function.getEntryPoint()

    try:
        function.setName(name, SourceType.USER_DEFINED)
    except Exception as e:
        print("ERROR: cannot rename %s to %s: %s" % (function.getEntryPoint(), name, e))
        return False

    return True


def set_signature(function, task_p):
    parameter = ParameterImpl("task", task_p, currentProgram)
    function.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED)
    function.replaceParameters(
        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
        True, SourceType.USER_DEFINED, parameter)


def define_task_function(value, name, task_p, taken):
    """Creates (or takes over) the function `value' points at and types it"""
    entry = to_addr(value & ~1)
    if not is_initialized(entry):
        print("ERROR: %s points outside of initialized memory (0x%08x)" % (name, value))
        return False

    function = getFunctionAt(entry)

    if function is None:
        container = getFunctionContaining(entry)
        if container is not None:
            print("Removing %s, it swallows %s at %s" %
                  (container.getName(), name, entry))
            removeFunction(container)

        if not disassemble_entry(entry, bool(value & 1)):
            print("ERROR: failed to disassemble %s at %s" % (name, entry))
            return False

        function = createFunction(entry, name)

        if function is None:
            print("ERROR: failed to create %s at %s" % (name, entry))
            return False

    if not rename(function, name, taken):
        return False

    try:
        set_signature(function, task_p)
    except Exception as e:
        print("ERROR: cannot set the signature of %s: %s" % (name, e))
        return False

    return True


def define_task_functions(start, count, layout, task):
    task_p = PointerDataType.getPointer(task, currentProgram.getDataTypeManager())
    taken = {}
    created = 0
    names = 0

    monitor.setIndeterminate(False)
    monitor.initialize(count)
    monitor.setCancelEnabled(True)
    monitor.setMessage("Creating task functions...")

    for index in range(count):
        if monitor.isCancelled():
            break

        monitor.incrementProgress(1)

        task_addr = start.add(index * task.getLength())
        name = task_name_of(task_addr, layout)

        if define_task_name(to_addr(read_u32(task_addr.add(layout["task_name_ptr"]))), name):
            names += 1

        for offset, suffix in ((layout["task_main_fn"], "Main"),
                               (layout["task_pre_fn"], "PreMain")):
            value = read_u32(task_addr.add(offset))
            if not value:
                continue

            function = "%s_%s" % (name, suffix)

            if define_task_function(value, function, task_p, taken):
                created += 1
                if SHOW_OUTPUT:
                    print("[%d/%d] %s @ %s" % (index + 1, count, function, to_addr(value & ~1)))

    print("Created %d task name strings" % names)
    print("Created or renamed %d task functions" % created)


def main():
    monitor.setIndeterminate(True)
    monitor.setCancelEnabled(True)

    soc, version = find_soc()
    expected = SOC_LAYOUT.get(soc)

    if soc is None:
        print("WARNING: no SoC-ID found, every task layout will be tried")
    elif expected is None:
        print("WARNING: SoC %s (%s) has no known task layout, every task layout will be tried" %
              (soc, version))
    else:
        print("SoC %s (%s), %s task layout" % (soc, version, expected["name"]))

    layout, stride, start, count = find_task_list(layout_preference(expected))

    if count < MIN_TASKS:
        print("ERROR: no task list found (best candidate had %d tasks)" % count)
        return

    if expected is not None and layout is not expected:
        print("WARNING: %s implies the %s layout, but the task list matches %s" %
              (soc, expected["name"], layout["name"]))

    print("Found %d tasks at %s using the %s layout, 0x%x bytes each" %
          (count, start, layout["name"], stride))

    task = create_types(layout, stride)

    if task is None:
        return

    if not label_task_list(start, count, task):
        return

    define_task_functions(start, count, layout, task)

    print("Done!")


if __name__ == "__main__":
    main()
