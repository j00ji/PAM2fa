# Nome do módulo
MODULE = pam_telegram_2fa

# Diretórios
SRC_DIR = .
BUILD_DIR = .
INSTALL_DIR = /lib64/security

# Bibliotecas e includes
INCLUDES = -I/usr/include/security -I/usr/include/x86_64-linux-gnu/curl
LIBS = -lcurl

# Flags do compilador
CFLAGS = -fPIC -fno-stack-protector -Wall -Wextra
LDFLAGS = -shared

# Alvo padrão: compilar e instalar
all: install

# Compilar o módulo
$(MODULE).so: $(MODULE).o
	ld $(LDFLAGS) $(LIBS) -o $(BUILD_DIR)/$@ $(BUILD_DIR)/$<

$(MODULE).o: $(SRC_DIR)/$(MODULE).c
	gcc $(CFLAGS) $(INCLUDES) -c -o $(BUILD_DIR)/$@ $<

# Instalar o módulo no diretório do PAM
install: $(MODULE).so
	@if [ ! -d $(INSTALL_DIR) ]; then \
		echo "Erro: Diretório $(INSTALL_DIR) não encontrado! Verifique a instalação do PAM."; \
		exit 1; \
	fi
	cp $(BUILD_DIR)/$(MODULE).so $(INSTALL_DIR)/$(MODULE).so
	@echo "Módulo instalado em $(INSTALL_DIR)"

# Limpar arquivos antigos (incluindo os instalados)
clean:
	rm -f ./pam_telegram_2fa.o ./pam_telegram_2fa.so
	sudo rm -f /lib64/security/pam_telegram_2fa.so
	@echo "Cleaned up."

# Testar se o módulo está carregado corretamente
test:
	@if [ -f $(INSTALL_DIR)/$(MODULE).so ]; then \
		ldd $(INSTALL_DIR)/$(MODULE).so; \
	else \
		echo "Erro: Módulo $(MODULE).so não encontrado em $(INSTALL_DIR)!"; \
	fi

# Desinstalar o módulo
uninstall:
	rm -f $(INSTALL_DIR)/$(MODULE).so
	@echo "Módulo removido de $(INSTALL_DIR)"
