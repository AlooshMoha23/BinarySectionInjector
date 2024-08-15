#  Project: Isos Inject - Injecting Code into ELF Binaries
Introduction:

Isos Inject is a tool designed to inject arbitrary code into ELF binaries. This project aims to provide students with hands-on experience in manipulating ELF files and understanding the underlying mechanisms of code injection.

Functionality:

Isos Inject takes five arguments:

1. Target ELF file: The ELF binary to be injected.
2. Injected code file: A binary file containing the machine code to be injected.
3. New section name: The name to be assigned to the newly created section.
4. Base address: The base address of the injected code.
5. Modify entry point: A boolean flag indicating whether to modify the entry point of the binary.
   
Usage:

1. Compile the provided assembly code using nasm.
2 Run Isos Inject with the required arguments.
3 The tool will inject the code into the target ELF file, creating a new section and updating the program headers accordingly.
4. If the modify entry point flag is set, the entry point of the binary will be modified to call the injected code.
   
Challenges:

The project is divided into seven challenges, each focusing on a specific aspect of ELF manipulation and code injection:

1. Initialize ELF file for reading.
2. Find the PT_NOTE segment header.
3. Inject the code into the binary.
4. Overwrite the concerned section header.
5. Calibrate section headers.
6. Overwrite the PT_NOTE program header.
7. Execute the injected code.

# To test the project use make help


Additional Notes:

1. The project utilizes the libbfd library for ELF file manipulation.
2. The injected code should be compiled into a raw binary file using the -f bin option of nasm.
3. The tool can also be used to hijack GOT entries and replace existing library calls with the injected code.
