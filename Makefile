GCC = /usr/bin/gcc
LIB = -l pthread
DEBUG = f
BASICOPTIONS = -Wall -O2 -s
ifeq ($(DEBUG),t)
	OPTIONS = $(BASICOPTIONS) -g
else
	OPTIONS = $(BASICOPTIONS)
endif
INCLUDE = 
CFLAGS = $(INCLUDE) $(OPTIONS)

OBJS_TUN = ustun.o inout.o common.o filter.o clist.o state.o logger.o ctrl.o
OBJS_TABLES = us6tables.o common.o filter.o commands.o clist.o state.o logger.o
OBJS_CTRL = usctrl.o common.o filter.o logger.o state.o clist.o ctrl.o
EXE = ustun us6tables usctrl

# All targets
all:		$(EXE)
		@if [ "$(DEBUG)" = "t" ]; then echo 'IMPORTANT: COMPILED WITH DEBUGINFO!!'; fi

ustun:		$(OBJS_TUN) $(USER_OBJS)
		@echo 'Building target: $@'
		@echo 'Invoking: GCC C++ Linker'
		$(GCC) $(LIB) -o ustun $(OBJS_TUN) $(LIBS)
		@echo 'Finished building target: $@'
		@echo ' '

us6tables:	$(OBJS_TABLES) $(USER_OBJS)
		@echo 'Building target: $@'
		@echo 'Invoking: GCC C++ Linker'
		$(GCC) $(LIB) -o us6tables $(OBJS_TABLES) $(LIBS)
		@echo 'Finished building target: $@'
		@echo ' '

usctrl:		$(OBJS_CTRL) $(USER_OBJS)
		@echo 'Building target: $@'
		@echo 'Invoking: GCC C++ Linker'
		$(GCC) $(LIB) -o usctrl $(OBJS_CTRL) $(LIBS)
		@echo 'Finished building target: $@'
		@echo ' '

%.o:		%.c incs/%.h incs/common.h
		@echo 'Building file: $<'
		@echo 'Invoking: GCC C++ Compiler'
		$(GCC) -DSOURCE_$(basename $@) -c $(CFLAGS) -o"$@" "$<"
		@echo 'Finished building: $<'
		@echo ' '

clean:
		rm *.o ustun us6tables usctrl

install:
		/usr/bin/install -t /usr/local/sbin/ -v $(EXE)
