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
}

# Task names that every Shannon image seen so far schedules
ANCHOR_TASK_NAMES = ["GLAPD", "PDNMGR", "SAEL3", "MSD_OT"]

SOC_PATTERN = "[S][0-9]{3,4}(AP)?"
SOC_TOKEN = re.compile(r"^S[0-9]{3,4}(AP)?")
SOC_SEARCH_CHUNK = 0x800000

TASK_NAME = re.compile(r"^[A-Za-z0-9_]{2,24}$")
TASK_NAME_MAX = 32

# A candidate array has to hold at least this many tasks to be believable
MIN_TASKS = 16
MAX_TASKS = 4096

# Change to false if you don't want your output window to be spammed
SHOW_OUTPUT = True


def read_u32(addr):
    try:
        return getInt(addr) & 0xFFFFFFFF
    except Exception:
        return None


def to_addr(value):
    try:
        return toAddr(value)
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


def search_chunks():
    """Initialized memory in ascending address order, in searchable slices"""
    for block in currentProgram.getMemory().getBlocks():
        if not block.isInitialized():
            continue
        offset = block.getStart().getOffset()
        end = block.getEnd().getOffset()
        while offset <= end:
            last = min(offset + SOC_SEARCH_CHUNK - 1, end)
            yield AddressSet(toAddr(offset), toAddr(last))
            offset = last + 1


def find_soc():
    """Locates the first SoC-ID string that we know the task layout of"""
    monitor.setMessage("Searching for the SoC version string...")

    for chunk in search_chunks():
        if monitor.isCancelled():
            return None, None

        for hit in findBytes(chunk, SOC_PATTERN, 64, 1):
            text = read_ascii(hit, 64)
            match = SOC_TOKEN.match(text)
            if match is None:
                continue
            soc = match.group(0)
            # a longer digit run is not a SoC-ID
            if len(text) > len(soc) and text[len(soc)].isdigit():
                continue
            if soc in SOC_LAYOUT:
                return soc, text

    return None, None


def layout_preference(soc):
    if soc is None:
        return [SAMSUNG_CORTEX_A, SAMSUNG_CORTEX_R]
    preferred = SOC_LAYOUT[soc]
    others = [other for other in (SAMSUNG_CORTEX_A, SAMSUNG_CORTEX_R) if other is not preferred]
    return [preferred] + others


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
    if task_name_of(task, layout) is None:
        return False
    main_fn = read_u32(task.add(layout["task_main_fn"]))
    if not main_fn:
        return False
    return is_initialized(to_addr(main_fn & ~1))


def measure_array(anchor, layout):
    """Grows a task array around `anchor', a candidate Task base address"""
    if not is_task(anchor, layout):
        return None, 0

    size = layout["task_size"]
    start = anchor
    while start.getOffset() > size:
        previous = start.subtract(size)
        if not is_task(previous, layout):
            break
        start = previous

    count = 0
    while count < MAX_TASKS and is_task(start.add(count * size), layout):
        count += 1

    return start, count


def anchor_candidates():
    """Addresses that may hold the name pointer of a well known task"""
    base = currentProgram.getMinAddress()

    for anchor in ANCHOR_TASK_NAMES:
        monitor.setMessage("Searching for task name '%s'..." % anchor)

        for string_addr in findBytes(base, "\\x00%s\\x00" % anchor, 8, 1):
            name_addr = string_addr.add(1)
            pattern = "".join(
                ["\\x%02x" % ((name_addr.getOffset() >> shift) & 0xFF) for shift in (0, 8, 16, 24)])

            monitor.setMessage("Searching for references to '%s'..." % anchor)

            for xref in findBytes(base, pattern, 8, 4):
                yield xref

        if monitor.isCancelled():
            return


def find_task_list(layouts):
    """Returns (layout, array start, task count) of the best candidate found"""
    best = (None, None, 0)

    for xref in anchor_candidates():
        if monitor.isCancelled():
            break

        for layout in layouts:
            base = xref.subtract(layout["task_name_ptr"])
            start, count = measure_array(base, layout)

            if count > best[2]:
                best = (layout, start, count)

            # the preferred layout matching this well is as good as it gets
            if count >= MIN_TASKS and layout is layouts[0]:
                return best

        if best[2] >= MIN_TASKS:
            return best

    return best


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


def create_types(layout):
    dtm = currentProgram.getDataTypeManager()
    uint = UnsignedIntegerDataType.dataType
    size = currentProgram.getDefaultPointerSize()
    pointer = PointerDataType.getPointer(None, dtm)

    task = ensure_struct("Task", layout["task_size"], [
        (layout["task_stackbase"], pointer, "stackbase"),
        (layout["task_name_ptr"], PointerDataType.getPointer(CharDataType.dataType, dtm), "name"),
        (layout["task_sched_prio"], ByteDataType.dataType, "sched_prio"),
        (layout["task_stacksize"], uint, "stacksize"),
        (layout["task_main_fn"], pointer, "main"),
        (layout["task_pre_fn"], pointer, "pre_main"),
    ], True)

    if task is None:
        return None, None

    name_size = layout["subtask_name_size"]
    subtask = ensure_struct("SubTask", layout["subtask_task_p"] + size, [
        (layout["subtask_magic"], uint, "magic"),
        (layout["subtask_name"], ArrayDataType(CharDataType.dataType, name_size, 1), "name"),
        (layout["subtask_task_p"], PointerDataType.getPointer(task, dtm), "task"),
    ], False)

    return task, subtask


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
    """Types the task name, taking the bytes back from any overlapping string"""
    data = getDataAt(addr)
    if data is not None and data.hasStringValue() and data.getLength() == len(name) + 1:
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

        task_addr = start.add(index * layout["task_size"])
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

    if soc is None:
        print("WARNING: no known SoC-ID found, both task layouts will be tried")
    else:
        print("SoC %s (%s), %s task layout" % (soc, version, SOC_LAYOUT[soc]["name"]))

    layouts = layout_preference(soc)
    layout, start, count = find_task_list(layouts)

    if count < MIN_TASKS:
        print("ERROR: no task list found (best candidate had %d tasks)" % count)
        return

    if soc is not None and layout is not SOC_LAYOUT[soc]:
        print("WARNING: %s implies the %s layout, but the task list matches %s" %
              (soc, SOC_LAYOUT[soc]["name"], layout["name"]))

    print("Found %d tasks at %s using the %s layout" % (count, start, layout["name"]))

    task, subtask = create_types(layout)

    if task is None or subtask is None:
        return

    if not label_task_list(start, count, task):
        return

    define_task_functions(start, count, layout, task)

    print("Done!")


if __name__ == "__main__":
    main()
