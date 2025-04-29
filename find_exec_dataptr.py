import idc
import idaapi
import idautils

def is_executed_indirect_call_or_jmp(ea, target_ea):
    """Check if the instruction at ea is an indirect call/jmp to target_ea."""
    mnem = idc.print_insn_mnem(ea)
    op_type = idc.get_operand_type(ea, 0)
    op_value = idc.get_operand_value(ea, 0)

    # We're only interested in indirect call/jmp using memory operands
    if mnem in ("call", "jmp"):
        # Operand type 2 = memory reference, 3 = phrase, 4 = displacement
        if op_type in [2, 3, 4]:
            if op_value == target_ea:
                return True
    return False

def get_data_qwords(start_ea, end_ea):
    """Yield qword addresses in the .data section."""
    ea = start_ea
    while ea < end_ea:
        if idc.get_item_size(ea) == 8:
            yield ea
        ea = idc.next_head(ea, end_ea)

def main():
    # Locate the .data segment
    data_seg = None
    for seg_ea in idautils.Segments():
        if idc.get_segm_name(seg_ea) == ".data":
            data_seg = idaapi.getseg(seg_ea)
            break

    if not data_seg:
        print("[-] .data segment not found.")
        return

    print("[*] Scanning .data qwords for executable usage...")

    for qword_ea in get_data_qwords(data_seg.start_ea, data_seg.end_ea):
        qword_name = idc.get_name(qword_ea) or "<unnamed>"

        for xref in idautils.XrefsTo(qword_ea):
            if is_executed_indirect_call_or_jmp(xref.frm, qword_ea):
                func_name = idc.get_func_name(xref.frm)
                print(f"[+] Qword at {qword_ea:#x} ('{qword_name}') is EXECUTED via {idc.print_insn_mnem(xref.frm)} at {xref.frm:#x} in function '{func_name}'")
                break  # Report once per qword

if __name__ == "__main__":
    main()
