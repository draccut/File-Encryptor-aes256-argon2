CC = gcc
# keine Compiler-Optimierungen (-O0)
CFLAGS = -O \
        -fstack-protector-strong \
        -fstrict-flex-arrays=3 \
        -fno-strict-aliasing \
        -fno-strict-overflow \
        -fno-delete-null-pointer-checks \
        -fcf-protection=full \
        -Wall -Wextra -Wformat -Wformat-security \
        -fPIE

LDFLAGS = -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack

ARGON2_DIR = phc-winner-argon2
ARGON2_REPO = https://github.com/P-H-C/phc-winner-argon2.git
INCLUDES = -I $(ARGON2_DIR)/include
LIBS = $(ARGON2_DIR)/libargon2.a

SRCS = aes.c sha256.c hmac.c main.c
TARGET = AES256

.PHONY: all argon2 clean

all: argon2 $(TARGET)

argon2:
	@if [ ! -d "$(ARGON2_DIR)" ]; then \
                echo "Cloning Argon2..."; \
                git clone --depth 1 $(ARGON2_REPO) $(ARGON2_DIR); \
        fi
	$(MAKE) -C $(ARGON2_DIR)

$(TARGET): $(SRCS) $(LIBS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(SRCS) $(LIBS) $(LDFLAGS)

test: CFLAGS += -D_TEST
test: argon2
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(SRCS) $(LIBS) $(LDFLAGS)

clean:
	rm -f $(TARGET)
	rm -rf $(ARGON2_DIR)

