# shemu (SHell + EMULATOR)
-(non-Volatility) Requirements:

  1) Unicorn (https://github.com/unicorn-engine/unicorn ) must be installed.
  2) Capstone (https://github.com/aquynh/capstone) must be installed.
  
- What are these files?

  shemulator.py is a (very slightly) modified version of volshell. All that was added was a function (emu()) which calls into      shemulator_api.py. shemulator_api contains a python class to handle creating a unicorn instance and letting the user interact with it as they want. 
  
- How do I set this up?

  Once you've installed unicorn and capstone, move volshell.py out of the plugins directory. Then add in shemulator_api.py and shemulator.py, but rename shemulator.py 'volshell.py' (We're sorry.)
  
- Why the whole song and dance with volshell?

  We wanted to extend the functionality of volshell, not replace any of it, so we thought the best way to go about this was simply editing the existing plugin. Unfortunately, this means having to replace volshell to not run into issues with certain classes already being defined (if both shemulator and volshell are in the plugins directory) or with things depending on volshell not being able to access it (if we remove volshell but don't rename shemulator). (We're still sorry)
  
- What does all of this actually do?

  shemu extends volshell to include some debugger-like functionality that (to the best of our knowledge) was not present before. By calling the emu() function, the user can begin emulating code at a specified address. 
  
  There are options to:
  
  *set breakpoints at certain addresses,
  
  *step through the emulation instruction by instruction,
  
  *set and read register values,
  
  *collect the starting addresses of new basic blocks being visited, and 
  
  *dump the emulated code into text files
  
  All of this should make using volatility to analyze code a much more pleasant task, alleviating the need to dump process memory and throw it into IDA to do any sort of dynamic analysis (though that is still probably prefferable for more intensive tasks).
  
- How do I run your code?

  Once you run volshell, you simply run the 'emu()' command with whatever options you want. The anatomy of emu() is:
  
  emu( address = integer, step = 1 or 0, max_inst = integer, dis_mode = 64 if 64 bit, otherwise ignore, print_regs = ['register1', 'register2', ...], stuff = {'register':integer, 'register2':integer, ...}, inst_dump = 1 or 0, dump_blocks = 1 or 0, v = 1 or 0, patch = {integer:'\xCO\xDE',...}, brk = [integer, integer, ....], dump_dir = 'some_directory')
  
  address is the address at which to start the emulation. No default.
  
  step controls if you are stepping through the emulation (and given control to issue a set of commands after each instruction). Default 0.
  
  max_inst gives the maximum number of instructions to execute. Default 100.
  
  dis_mode tells shemulator to be in 64 bit or 32 bit mode. Default 32.
  
  print_regs is a list of registers you want to print out throughout the program. Default ['eax', 'ebx', 'ecx', 'edx'].
  
  stuff is a dictionary of 'register':value pairs, where each register is initialized with the corresponding value. Default {}
  
  inst_dump controls if, when printing registers, to do so after each instruction (if inst_dump is 1) or at the end of each basic block (if 0). Default 0.
  
  dump_blocks controls if shemulator prints the starting addresses of each basic block visited during emulation, after emulation is finished. Default 0.
  
  v controls verbosity, i.e. if the instructions are printed as emulation happens (if 1) or not (if 0). Default 1.
  
  patch is a dictionary of address:'\xCO\xDE' pairs, where, when the listed addresses are mapped into memory, the true values are overwritted with the supplied code. Default {}.
  
  brk is a list of addresses to set breakpoints on. Default []
  
  dump_dir controls if you want to dump all the emulated code into whatever supplied directory. Default is '', creating no directory and dumping no code.

- How do I know it works?
  We've created two memory images (64 and 32 bit windows 10) running a dummy program we wrote. Here are links to the program, the ida.db, and the memory images: TODO
  
  In the 64 bit system, the PID is 2928 and the body of the program starts at TODO
  
  In the 32 bit system, the PID is 9632 and the body starts at 0x3724a0. In this case, to begin emulation from inside volshel (and the correct context), type:
  
  emu(0x3724a0)
  
  with whatever options you want.
  
- Who worked on this (Alphabetically)?

  Sweta Ghimire, Ryan Maggio, Raphaela Mettig of the Louisiana State University Cybersecurity Lab
