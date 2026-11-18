# Instalação

```bash
git clone https://github.com/Hase505/port-scanner-scapy.git
cd port-scanner-scapy
pip install -r requirements.txt
```

# Uso

```
python main.py IP -p PORTA(S) -t TECNICA [-T TIMEOUT]
```

| Argumento | Descrição |
|---|---|
| IP | Endereço IP de destino |
| -p, --ports | Portas: 80, 80,443 ou 1-1000 (combináveis: 22,80,8000-8100) |
| -t, --type | Técnica de scan: syn, udp ou xmas |
| -T, --timeout | Tempo de espera por porta, em segundos (padrão: 2) |

## Exemplos

```bash
# SYN scan nas portas 1 a 1000
sudo python main.py 192.168.0.1 -p 1-1000 -t syn

# UDP scan em portas específicas com timeout de 3s
sudo python main.py 192.168.0.1 -p 53,123,161 -t udp -T 3

# XMAS scan com timeout reduzido
sudo python main.py 192.168.0.1 -p 20-25,80,443 -t xmas -T 0.5
```

