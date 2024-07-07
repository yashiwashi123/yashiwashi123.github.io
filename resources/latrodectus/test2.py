import idaapi
import idautils
import idc

# Address of the function
function_address = 0x00000001800099FC  # Replace with the actual address of your function

def get_rcx_value_from_lea(ea):
    """
    Get the value loaded into RCX from the first LEA instruction at the given address.
    """
    try:
        for head in idautils.Heads(ea, idc.BADADDR):
            if idc.print_insn_mnem(head) == "lea" and idc.print_operand(head, 0) == "rcx":
                return idc.get_operand_value(head, 1)
    except Exception as e:
        print(f"Exception in get_rcx_value_from_lea: {e}")
    return None

def read_memory_at_address(addr, length):
    """
    Read `length` bytes from the memory at `addr`.
    """
    return idc.get_bytes(addr, length)

def main():
    rcx_values = []
    try:
        for xref in idautils.XrefsTo(function_address):
            ea = xref.frm
            # Find the function containing the xref
            func = idaapi.get_func(ea)
            if func:
                rcx_value = get_rcx_value_from_lea(func.start_ea)
                if rcx_value is not None:
                    rcx_values.append(rcx_value)
            else:
                print(f"No function found containing address: {hex(ea)}")
    except Exception as e:
        print(f"Exception in main: {e}")
    
    # Print the memory bytes at the addresses in hexadecimal format
    for value in rcx_values:
        bytes_read = read_memory_at_address(value, 16)  # Read 16 bytes, adjust as needed
        if bytes_read:
            hex_bytes = bytes_read.hex()
            print(f"Address: {hex(value)}, Data: {hex_bytes}")
        else:
            print(f"Address: {hex(value)}, Data: None")

if __name__ == "__main__":
    main()