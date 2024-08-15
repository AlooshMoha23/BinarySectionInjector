#include <argp.h>
#include <bfd.h>
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

const char *argp_program_version = "isos_inject 1.0";
const char *argp_program_bug_address = "<bafaqas2000@gmail.com>";

/* Program documentation. */
static char doc[] = "isos_inject is a tool that allows you to inject new code "
                    "sections into an ELF binary.";

/* A description of the arguments we accept. */
static char args_doc[] =
    "elf_file machine_code section_name base_address modify_entry";

/* The options we understand. */
static struct argp_option options[] = {
    {"elf_file", 'e', "FILE", 0, "Path to the ELF file to be analyzed", 0},
    {"machine_code", 'm', "FILE", 0,
     "Path to the binary file that contains the machine code to be injected",
     0},
    {"section_name", 'n', "NAME", 0, "Name of the newly created section", 0},
    {"base_address", 'b', "ADDRESS", 0, "Base address of the injected code", 0},
    {"modify_entry", 'f', "BOOL", 0,
     "Boolean indicating whether the entry function should be modified", 0},
    {0}};

/* Used by main to communicate with parse_opt. */
struct arguments {
  char *elf_file, *machine_code, *section_name;
  unsigned long base_address;
  int modify_entry;
};

/* Parse a single option. */
static error_t parse_opt(int key, char *arg, struct argp_state *state) {
  /* Get the input argument from argp_parse, which we know is a pointer to our
   * arguments structure. */
  struct arguments *arguments = state->input;

  switch (key) {
  case 'e':
    if (!strcmp(arg, "")) {
      fprintf(stderr, "elf_file is required\n");
      return ARGP_ERR_UNKNOWN;
    }
    arguments->elf_file = arg;
    break;
  case 'm':
    if (!strcmp(arg, "")) {
      fprintf(stderr, "machine_code is required\n");
      return ARGP_ERR_UNKNOWN;
    }
    arguments->machine_code = arg;
    break;
  case 'n':
    if (!strcmp(arg, "")) {
      fprintf(stderr, "section_name is required\n");
      return ARGP_ERR_UNKNOWN;
    }
    arguments->section_name = arg;
    break;
  case 'b':
    if (!strcmp(arg, "")) {
      fprintf(stderr, "base_address is required\n");
      return ARGP_ERR_UNKNOWN;
    }
    arguments->base_address = strtoul(arg, NULL, 0);
    break;
  case 'f':
    if (!strcmp(arg, "")) {
      fprintf(stderr, "modify_entry is required\n");
      return ARGP_ERR_UNKNOWN;
    }
    arguments->modify_entry = atoi(arg);
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

/* Our argp parser. */
static struct argp argp = {options, parse_opt, args_doc, doc, .children = NULL};

int main(int argc, char **argv) {
  struct arguments arguments;

  /* Default values. */
  arguments.elf_file = NULL;
  arguments.machine_code = NULL;
  arguments.section_name = NULL;
  arguments.base_address = 0;
  arguments.modify_entry = -1;

  /* Parse our arguments; every option seen by parse_opt will be reflected in
   * arguments. */
  argp_parse(&argp, argc, argv, ARGP_IN_ORDER, 0, &arguments);

  /* Check if all arguments are provided */
  if (arguments.elf_file == NULL || arguments.machine_code == NULL ||
      arguments.section_name == NULL || arguments.base_address == 0 ||
      arguments.modify_entry == -1) {
    fprintf(stderr, "All arguments are mandatory\nTry `isos_inject --help' or "
                    "`isos_inject --usage' for more information.\n");
    return 1;
  }

  printf("ELF_FILE = %s\nMACHINE_CODE = %s\nsection_name = %s\nBASE_ADDRESS = "
         "%lu\nMODIFY_ENTRY = %d\n",
         arguments.elf_file, arguments.machine_code, arguments.section_name,
         arguments.base_address, arguments.modify_entry);

  /* Initialize the BFD library. */
  bfd_init();

  /* Open the ELF file. */
  bfd *abfd;
  abfd = bfd_openr(arguments.elf_file, NULL);

  if (abfd == NULL) {
    bfd_perror("bfd_openr");
    return 1;
  }

  /* Check if the file is an ELF file. */
  if (bfd_check_format(abfd, bfd_object) == 0) {
    fprintf(stderr, "%s is not ELF format\n", arguments.elf_file);
    return 1;
  }

  /* Check if the file is 64-bit. */
  if (bfd_get_arch_size(abfd) != 64) {
    fprintf(stderr, "%s is not a 64-bit binary\n", arguments.elf_file);
    return 1;
  }

  /* Check if the file is executable. */
  if ((abfd->flags & EXEC_P) == 0) {
    fprintf(stderr, "%s is not an executable\n", arguments.elf_file);
    return 1;
  }

  /*-----------------------------------------------------------------------------------------------------------------------------*/
  /*                                             task2 */
  /*-----------------------------------------------------------------------------------------------------------------------------*/
  int fd;
  Elf64_Ehdr *map_start;
  Elf64_Ehdr *header;
  Elf64_Phdr *pheader;
  int i;

  if ((fd = open(arguments.elf_file, O_RDONLY)) < 0) {
    perror("error in open");
    exit(-1);
  }

  // Map the ELF file into memory

  if ((map_start = (Elf64_Ehdr *)mmap(0, 0x1000, PROT_READ, MAP_PRIVATE, fd,
                                      0)) == (Elf64_Ehdr *)MAP_FAILED) {
    perror("error in mmap");
    exit(-1);
  }

  header = map_start;
  pheader = (Elf64_Phdr *)((uintptr_t)map_start + header->e_phoff);

  int PT_NOTE_index = 0;
  // Loop through the program headers to find the PT_NOTE section

  for (i = 0; i < header->e_phnum; i++) {
    if (pheader[i].p_type == PT_NOTE) {
      PT_NOTE_index = i;
      printf("Found PT_NOTE at index %d\n", PT_NOTE_index);
      break;
    }
  }

  // Unmap the memory and close the file

  munmap(map_start, 0x1000);
  close(fd);

  /*-----------------------------------------------------------------------------------------------------------------------------*/
  /*                                             task3 */
  /*-----------------------------------------------------------------------------------------------------------------------------*/

  int fd2;
  struct stat st;
  void *map_start2;

  if ((fd2 = open(arguments.elf_file, O_RDWR)) < 0) {
    perror("error in open");
    exit(-1);
  }

  // Get the size of the file
  if (fstat(fd2, &st) < 0) {
    perror("error in fstat");
    exit(-1);
  }

  // Map the ELF file into memory
  if ((map_start2 = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd2,
                         0)) == MAP_FAILED) {
    perror("error in mmap");
    exit(-1);
  }

  // Open the injection code file
  int fd_inject;
  struct stat st_inject;
  void *map_start_inject;

  if ((fd_inject = open(arguments.machine_code, O_RDONLY)) < 0) {
    perror("error in open");
    exit(-1);
  }

  // Get the size of the injection code file
  if (fstat(fd_inject, &st_inject) < 0) {
    perror("error in fstat");
    exit(-1);
  }

  // Map the injection code file into memory
  if ((map_start_inject = mmap(0, st_inject.st_size, PROT_READ, MAP_PRIVATE,
                               fd_inject, 0)) == MAP_FAILED) {
    perror("error in mmap");
    exit(-1);
  }

  // Append the injection code to the end of the ELF file
  off_t offset = lseek(fd2, 0, SEEK_END);
  printf("offset before %ld\n", offset);
  write(fd2, map_start_inject, st_inject.st_size);

  // Compute the address so that the difference with the file offset becomes
  // zero modulo 4096
  int res = (((uintptr_t)arguments.base_address - offset) % 4096);
  if (res != 0) {

    arguments.base_address =
        (unsigned long)((uintptr_t)arguments.base_address + res);
  }

  while ((((uintptr_t)arguments.base_address - offset) % 4096) != 0) {

    arguments.base_address +=
        (((uintptr_t)arguments.base_address - offset) % 4096);
  }
  printf("mod  %ld\n", ((uintptr_t)arguments.base_address - offset) % 4096);

  // Unmap the memory and close the files
  munmap(map_start2, st.st_size);
  munmap(map_start_inject, st_inject.st_size);
  close(fd2);
  close(fd_inject);

  /*-----------------------------------------------------------------------------------------------------------------------------*/
  /*                                             task4 */
  /*-----------------------------------------------------------------------------------------------------------------------------*/

  Elf64_Shdr *sheader;
  int fd3;
  void *map_start3;

  if ((fd3 = open(arguments.elf_file, O_RDWR)) < 0) {
    perror("error in open");
    exit(-1);
  }

  // Map the ELF file into memory
  if ((map_start3 = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd3,
                         0)) == MAP_FAILED) {
    perror("error in mmap");
    exit(-1);
  }

  header = map_start3;
  sheader = (Elf64_Shdr *)((uintptr_t)map_start3 + header->e_shoff);

  // Get the index number of the section header describing the .shstrtab section
  int shstrtab_index = header->e_shstrndx;

  // Loop overall section headers, inspecting each one as it goes along
  for (i = 0; i < header->e_shnum; i++) {
    // Inside the loop, get the name of each iterated section header
    char *name =
        (char *)((uintptr_t)map_start3 + sheader[shstrtab_index].sh_offset +
                 sheader[i].sh_name);

    // If the name of the current section is .note.ABI-tag, note its index and
    // overwrite the fields in the section header to turn it into a header
    // describing the injected section
    if (strcmp(name, ".note.ABI-tag") == 0) {
      sheader[i].sh_type = SHT_PROGBITS;
      sheader[i].sh_addr = arguments.base_address;
      sheader[i].sh_offset = offset;
      sheader[i].sh_size = st_inject.st_size;
      sheader[i].sh_addralign = 16;
      sheader[i].sh_flags |= SHF_EXECINSTR;

      // Once the header modifications are complete, write the modified section
      // header back into the ELF binary file
      lseek(fd3, header->e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET);
      write(fd3, &sheader[i], sizeof(Elf64_Shdr));
      break;
    }
  }

  // Unmap the memory and close the file
  munmap(map_start3, st.st_size);
  close(fd3);

  /*-----------------------------------------------------------------------------------------------------------------------------*/
  /*                                             task5 */
  /*-----------------------------------------------------------------------------------------------------------------------------*/

  int fd4;
  void *map_start4;

  if ((fd4 = open(arguments.elf_file, O_RDWR)) < 0) {
    perror("error in open");
    exit(-1);
  }

  // Map the ELF file into memory
  if ((map_start4 = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd4,
                         0)) == MAP_FAILED) {
    perror("error in mmap");
    exit(-1);
  }

  header = map_start4;
  sheader = (Elf64_Shdr *)((uintptr_t)map_start4 + header->e_shoff);

  // Get the index number of the section header describing the .shstrtab section
  shstrtab_index = header->e_shstrndx;

  // Loop overall section headers, inspecting each one as it goes along
  for (i = 0; i < header->e_shnum; i++) {
    // Inside the loop, get the name of each iterated section header
    char *name =
        (char *)((uintptr_t)map_start4 + sheader[shstrtab_index].sh_offset +
                 sheader[i].sh_name);

    // If the name of the current section is .note.ABI-tag, note its index and
    // overwrite the fields in the section header to turn it into a header
    // describing the injected section
    if (strcmp(name, ".note.ABI-tag") == 0) {

      // Set the Name of the Injected Section
      int name_offset = sheader[shstrtab_index].sh_offset + sheader[i].sh_name;
      lseek(fd4, name_offset, SEEK_SET);
      write(fd4, arguments.section_name, strlen(arguments.section_name) + 1);

      // Reorder Section Headers by Section Address
      int j = i;
      while (j > 0 && sheader[j - 1].sh_addr > sheader[j].sh_addr) {
        Elf64_Shdr temp = sheader[j];
        sheader[j] = sheader[j - 1];
        sheader[j - 1] = temp;
        j--;
      }
      while (j < header->e_shnum - 1 &&
             sheader[j + 1].sh_addr < sheader[j].sh_addr) {
        Elf64_Shdr temp = sheader[j];
        sheader[j] = sheader[j + 1];
        sheader[j + 1] = temp;
        j++;
      }

      // Update sh_link fields
      for (Elf64_Word k = 0; k < header->e_shnum; k++) {
        if (sheader[k].sh_link == (Elf64_Word)i) {
          sheader[k].sh_link = (Elf64_Word)j;
        } else if (sheader[k].sh_link > (Elf64_Word)i &&
                   sheader[k].sh_link <= (Elf64_Word)j) {
          sheader[k].sh_link--;
        } else if (sheader[k].sh_link < (Elf64_Word)i &&
                   sheader[k].sh_link >= (Elf64_Word)j) {
          sheader[k].sh_link++;
        }
      }

      // Write the reordered section headers back into the ELF file
      lseek(fd4, header->e_shoff, SEEK_SET);
      write(fd4, sheader, header->e_shnum * sizeof(Elf64_Shdr));

      break;
    }
  }

  // Unmap the memory and close the file
  munmap(map_start4, st.st_size);
  close(fd4);

  /*-----------------------------------------------------------------------------------------------------------------------------*/
  /*                                             task6 */
  /*-----------------------------------------------------------------------------------------------------------------------------*/

  int fd5;
  void *map_start5;

  if ((fd5 = open(arguments.elf_file, O_RDWR)) < 0) {
    perror("error in open");
    exit(-1);
  }

  // Map the ELF file into memory
  if ((map_start5 = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd5,
                         0)) == MAP_FAILED) {
    perror("error in mmap");
    exit(-1);
  }

  header = map_start5;
  pheader = (Elf64_Phdr *)((uintptr_t)map_start5 + header->e_phoff);

  // Overwrite the PT_NOTE program header to create a loadable segment that
  // contains the injected section
  pheader[PT_NOTE_index].p_type = PT_LOAD;
  pheader[PT_NOTE_index].p_flags |= PF_X;
  pheader[PT_NOTE_index].p_offset = offset;
  pheader[PT_NOTE_index].p_vaddr = arguments.base_address;
  pheader[PT_NOTE_index].p_paddr = arguments.base_address;
  pheader[PT_NOTE_index].p_filesz = st_inject.st_size;
  pheader[PT_NOTE_index].p_memsz = st_inject.st_size;
  pheader[PT_NOTE_index].p_align = 0x1000;
  // Write the modified program header back into the ELF file
  lseek(fd5, header->e_phoff + PT_NOTE_index * sizeof(Elf64_Phdr), SEEK_SET);
  write(fd5, &pheader[PT_NOTE_index], sizeof(Elf64_Phdr));

  // Unmap the memory and close the file
  munmap(map_start5, st.st_size);
  close(fd5);

  /*-----------------------------------------------------------------------------------------------------------------------------*/
  /*                                             task7 */
  /*-----------------------------------------------------------------------------------------------------------------------------*/

  int fd6;
  Elf64_Ehdr *map_start6;
  Elf64_Shdr *shdr;
  char *strtab;

  if ((fd6 = open(arguments.elf_file, O_RDWR)) < 0) {
    perror("error in open");
    exit(-1);
  }

  // Map the ELF file into memory
  if ((map_start6 = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd6,
                         0)) == MAP_FAILED) {
    perror("error in mmap");
    exit(-1);
  }

  header = map_start6;
  // Modify the entry point (optional)
  if (arguments.modify_entry) {

    // Modify the entry point of the ELF file to point to the injected code
    header->e_entry = arguments.base_address;
    // Write the modified ELF header back into the ELF file
    lseek(fd6, 0, SEEK_SET);
    write(fd6, header, sizeof(Elf64_Ehdr));
  }

  // Hijack the GOT entry
  // Find the .got.plt section
  shdr = (Elf64_Shdr *)((uintptr_t)header + header->e_shoff);
  strtab = (char *)header + shdr[header->e_shstrndx].sh_offset;
  Elf64_Shdr *gotplt_shdr = NULL;
  for (int i = 0; i < header->e_shnum; i++) {
    if (strcmp(strtab + shdr[i].sh_name, ".got.plt") == 0) {
      gotplt_shdr = &shdr[i];
      break;
    }
  }

  if (!gotplt_shdr) {
    fprintf(stderr, "Failed to find .got.plt section\n");
    exit(-1);
  }

  // Calculate the address of the GOT entry for fseeko
  Elf64_Addr fseeko_got_entry = 0x6101f8 - gotplt_shdr->sh_addr;

  // Overwrite the GOT entry with the address of the injected code
  *(Elf64_Addr *)((uintptr_t)map_start6 + fseeko_got_entry) =
      arguments.base_address;

  // Unmap the memory and close the file
  munmap(map_start6, st.st_size);
  close(fd6);

  return 0;
}
