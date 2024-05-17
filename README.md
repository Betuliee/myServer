Fatma Ozel nº 57037
Lilia Colisnyc nº 56949
Luiza maretto nº 58653

Exemplos de comandos:
Comandos incorretos com a mensagem de erro:
- [ ] mySNS -a 127.0.0.1:23456 -m —> Número insuficiente de argumentos para o modo médico (-m).
- [ ] mySNS -a 127.0.0.1:23456 -m silva —>  Número insuficiente de argumentos para o modo médico (-m).
- [ ] mySNS -a 127.0.0.1:23456 -m silva -u —> Número insuficiente de argumentos para o modo médico (-m).
- [ ] mySNS -a 127.0.0.1:23456 -m silva -u maria —> Número insuficiente de argumentos para o modo médico (-m).
- [ ] mySNS -a 127.0.0.1:23456 -m silva -u maria -sc —> Número insuficiente de argumentos para o modo médico (-m).
- [ ] mySNS -a 127.0.0.1:23456 -m silva -u maria -sc si3.pdf -a -e -s —> 
    Ficheiro: '-a' não existe.
    Ficheiro: '-e' não existe.
    Ficheiro: '-s' não existe.
- [ ] mySNS -a 127.0.0.1:23456 -ç silva -k maria -aac si3.pdf -a -e -s —> Formato inválido. Use '-u' para o username do utente ou '-m'    para o username do médico.
- [ ] mySNS -a 127.0.0.1:23456 —> Número insuficiente de argumentos. Use -u, ou -m.
- [ ] mySNS -a 127.0.0.1:23456 -k -g -sc -sa —> Formato inválido. Use '-u' para o username do utente ou '-m' para o username do médico.

Comandos corretos para cifrar, assinar, decifrar e validar os ficheiros:
- [ ] mySNS -a 127.0.0.1:23456 -m silva -u maria -sc si3.pdf biblia.pdf--> Cifra e gera a chave secreta
- [ ] mySNS -a 127.0.0.1:23456 -m silva -u maria -sa si3.pdf biblia.pdf--> Assina
- [ ] mySNS -a 127.0.0.1:23456 -m silva -u maria -se si3.pdf biblia.pdf--> Cifra, assina e gera a chave secreta
- [ ] mySNS -a 127.0.0.1:23456 -u maria -g si3.pdf biblia.pdf --> Recebe vários ficheiros e decifra e/ou valida assinatura # myServer
