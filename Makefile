# to edit
SRC_FILES := isos_inject.c  

vpath %.c ./src

build_dependencies: $(SRC_FILES:.c=.dep)
	@cat $^ > make.test
	@rm $^

%.dep: %.c
	@gcc -MM -MF $@ $<

# New target to run the Makefile in the src directory
src:
	$(MAKE) -C src all
	cp dateOriginal ./date
	./isos_inject --elf_file=date --machine_code=inject --section_name=new --base_address=0x500000 --modify_entry=14
	chmod +x date
	./date

# New clean target to clean the src directory
clean:
	$(MAKE) -C src clean
	rm date

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build_dependencies  Build dependencies for the src directory"
	@echo "  src                Compile the source code, create a duplicate of the ‘date’ binary, run the resulting program, and subsequently execute the ‘date’ program."
	@echo "  clean              Clean the directory"
	@echo "  help               Display this help information"	

.PHONY: src clean help
