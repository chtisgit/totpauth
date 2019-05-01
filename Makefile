
OTP := c_otp/src/rfc4226.o  c_otp/src/rfc6238.o c_otp/lib/utils.o
LIBS := -lm -lcrypto
CFLAGS := -g -O2 $(CFLAGS)

all: $(OTP) totpauth

totpauth: totpauth.c $(OTP)
	$(CC) $(CFLAGS) -o totpauth totpauth.c $(OTP) $(LIBS)

$(OTP):
	cd c_otp && $(MAKE) all

clean:
	$(RM) totpauth

.PHONY: all clean
