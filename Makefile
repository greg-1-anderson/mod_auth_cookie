APXS=apxs2
# location of apxs, if not in path
#APXS=/usr/local/apache2/bin/apxs
#APXS=/usr/sbin/apxs2

SOURCES=mod_auth_cookie.c
TARGETS=$(SOURCES:.c=.la)
LIBS=libmcrypt.so

all: $(TARGETS)

# build mod_auth_cookie
%.la: %.c
	$(APXS) -c $< $(LIBS)

# build sample program
crypt_sample: crypt_sample.c
	gcc -g -l mcrypt -l cgi $^ -o $@

install: $(TARGETS)
	$(APXS) -i $(TARGETS)
	if [ -d /etc/apache2/mods-available ] && [ ! -f /etc/apache2/mods-available/auth_cookie.load ] ; then \
		( \
			echo "LoadFile /usr/lib/libmcrypt.so"; \
			echo "LoadModule auth_cookie_module /usr/lib/apache2/modules/mod_auth_cookie.so" \
		) > /etc/apache2/mods-available/auth_cookie.load; \
		a2enmod auth_cookie; \
	fi
	if [ -f /etc/sysconfig/apache2 ] && [ "x`grep auth_cookie /etc/sysconfig/apache2`" == "x" ] ; then \
		sudo sed -i -e 's|^APACHE_MODULES="|APACHE_MODULES="auth_cookie |' /etc/sysconfig/apache2; \
	fi

clean:
	-rm -f $(TARGETS) *~ $(SOURCES:.c=.slo) $(SOURCES:.c=.lo) $(SOURCES:.c=.so) $(SOURCES:.c=.o) crypt_sample
