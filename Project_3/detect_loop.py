import angr # type: ignore
import sys
import os

def load_trace(trace_log):
    trace = []
    with open(trace_log, 'rb') as fr:
        for line in fr:
            addr, opcode = line.rstrip().split(',')
            trace.append({"address":addr, "opcode":opcode})
    return trace

def dynamic_call_sequence(func_list, trace):
    sequence = []
    ##### For Students
    ##### fill this function to return the call sequence
    ##### using the instruction trace of executed malware
    #####
    sequence = []
    func_addresses = {hex(func["address"]): func["address"] for func in func_list}
    
    for instruction in trace:
        if instruction["address"] in func_addresses:
            sequence.append(func_addresses[instruction["address"]])
    return sequence


def find_loop(sequence):
    loop_sequence = []
    ### For Students
    ### Find the functions repetead in the loop
    ### The malware tries to communicate with C&C server
    ### Since the communication is forbidden, 
    ### malware keep trying to establish a connection
    ###
    for window_size in range(20, 3, -1):
        for i in range(len(sequence) - window_size * 2):
            if sequence[i:i + window_size] == sequence[i + window_size:i + 2 * window_size]:
                loop_sequence = sequence[i:i + window_size]
                unique_loop_sequence = []
                seen = set()
                for addr in loop_sequence:
                    if addr not in seen:
                        unique_loop_sequence.append(addr)
                        seen.add(addr)

                return unique_loop_sequence

    return loop_sequence



def main():

    binary_path = sys.argv[1]
    if not os.path.exists(binary_path):
      print("Error: binary does not exist at %s" % binary_path)
      quit()
      
    proj = angr.Project(binary_path,
    use_sim_procedures=True,
    default_analysis_mode='symbolic',
    load_options={'auto_load_libs': False})

    proj.hook_symbol('lstrlenA', angr.SIM_PROCEDURES['libc']['strlen'])
    proj.hook_symbol('StrCmpNIA', angr.SIM_PROCEDURES['libc']['strncmp'])

    r2cfg = proj.analyses.Radare2CFGRecover()
    r2cfg._analyze(binary_path)

    flist = r2cfg.function_list()

    trace = load_trace('./instrace.linux.log')
    sequence = dynamic_call_sequence(flist, trace)

    loop = find_loop(sequence)
    print(loop)

    loop_str = [hex(addr) for addr in loop]
    print("Function List: " + ", ".join(loop_str))

if __name__ == "__main__":

  if(len(sys.argv) != 2):
    print("Usage: %s [target-program] " \
             % sys.argv[0])
    quit()
  main()
