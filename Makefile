SRC_DIR := src
INC_DIR := include
OBJ_DIR := obj
BIN_DIR := bin

EXE := $(BIN_DIR)/aes

SRC := $(wildcard $(SRC_DIR)/*.c)
OBJ := $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

CFLAGS := -Iinclude -MMD -MP
CPPFLAGS := -Wextra #Wall
LDFLAGS := -Llib
LDLIBS := -lm

.PHONY: all
all: $(EXE)

$(EXE): $(OBJ) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR): 
	mkdir $@

clean:
	@$(RM) -rv $(BIN_DIR) $(OBJ_DIR) leak_info.txt aes* null.d 
	
rebuild: clean all

-include $(OBJ:.o=.d)
