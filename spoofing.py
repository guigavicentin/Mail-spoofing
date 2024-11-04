
def install(package):
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])


try:
    import dns.resolver
except ImportError:
    print("dnspython não está instalado. Instalando agora...")
    install('dnspython')
    import dns.resolver  

def banner():
    print("======================================")
    print("       Mail Spoofing Checker         ")
    print("======================================")
    print(r"""
@@@@@%+..........................................................................+%@@@@@@
@@@@#-...............................:-=+*##*+==:.................................-#@@@@@
@@%=................................+@@@@@@@@@@@@#..................................+%@@@
@#:................................-%@@@@@@@@@@@@@=..................................-#@@
*..................................%@@@@@@@@@@@@@@%....................................#@
..................................=%@@@@@@@@@@@@@@@+....................................#
..........................:-==+**+=---=+*#%%#*+=---=+**+==--.............................
...........................:=*#%@@@@@%%#*+=-+*#%@@@@@@@%*=-..............................
................................-+%@@@@@@@@@@@@@@@@%+-:..................................
..................................:%@@@@@@@@@@@@@@@-.....................................
...................................=@@@@@@@@@@@@@@*......................................
....................................*@@@@@@@@@@@@%.......................................
:-=++=-..............................+%@@@@@@@@%+:...............................-=++=-:.
@@@@@@@%*-.............................-+%@@%*-...............................-*%@@@@@@@#
.......=@@*...............................==................................:#@@@:....%@@
..@@@..=@@@+........................:-...-@@*...--:.........................*@@@@*+:..%@@
..@@@..=@@@#..................:-+*%@@@*...*%...+@@@%#+=-....................%@@@@@@-..%@@
..@@@..=@@@*..............=*#%@@@@@@@@@=..+%..:%@@@@@@@@@%#*=:..............*@@@@@@-..%@@
.......=@@#..............*@@@@@@@@@@@@@%:.#@-.%@@@@@@@@@@@@@@%:.............:%@@@@@-..%@@
%%%%%%%%#=..............*@@@@@@@@@@@@@@@#:%@+#@@@@@@@@@@@@@@@@%:..............=#@@@%%%@@%
-=+**+=:...............=@@@@@@@@@@@@@@@@@%@@@@@@@@@@@@@@@@@@@@@*................:=+**+=-.
....:-................:%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+.................-......
.+-.:%+..............:%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=..............=%+.:+:..
.#@%#%@%-............#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@-...........:#@@#%@@:..
.+%@@@@@@#+=-:......*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%.......-=+*%@@@@@%*...
...:=#%@@@@@@@@%#*+*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#+*##%@@@@@@@@%+-.....
.......=@@@@@@@@@@@@@@@@@@@##@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@@@@@@@@@@@*:........
.......-@@@@@@@@@@@@@@@@@%+.-@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.=%@@@@@@@@@@@@@@@@@+.........
........:-+*#%@@@@@@@@@@%-...%@@@@@@@@@@@@@@@@@@@@@@@@@@@@%..:*@@@@@@@@@@%%*+=-.........:
..............:-=+*#%%@+.....#@@@@@@@@@@@@@@@@@@@@@@@@@@@@*....=%@%#*+=-:..............:%
%-....................:......+%%%%%%%%%%%%%%%%%%%%%%%%%%%%=...........................-%@
@%+..................................................................................*%@@
          """)

def get_target():
    target = input("Enter the target domain: ")
    return target

def check_spf_vulnerability(spf_record):
    if '+all' in spf_record:
        return "SPF vulnerable: Permissive (+all) allows any server to send emails."
    elif '-all' in spf_record:
        return "SPF configured correctly with -all (strict policy)."
    elif '~all' in spf_record:
        return "SPF configured with ~all (soft fail), which is less strict but generally acceptable."
    else:
        return "SPF configuration unclear or missing a terminating mechanism."

def check_mail_spoofing(target):
    try:
        # Verifica registros SPF
        spf_found, spf_status = False, "No SPF record found."
        try:
            spf_records = dns.resolver.resolve(target, 'TXT')
            for record in spf_records:
                record_text = str(record)
                if 'v=spf1' in record_text:
                    spf_found = True
                    spf_status = check_spf_vulnerability(record_text)
                    break
        except dns.resolver.NoAnswer:
            spf_status = "SPF record missing or DNS error."

        # Verifica registros DMARC
        dmarc_found, dmarc_status = False, "No DMARC record found."
        try:
            dmarc_record = '_dmarc.' + target
            dmarc_records = dns.resolver.resolve(dmarc_record, 'TXT')
            for record in dmarc_records:
                record_text = str(record)
                if 'v=DMARC1' in record_text:
                    dmarc_found = True
                    dmarc_status = "DMARC record found and configured."
                    break
        except dns.resolver.NoAnswer:
            dmarc_status = "DMARC record missing."
        except dns.resolver.NXDOMAIN:
            dmarc_status = "DMARC record not found (NXDOMAIN)."

        # Verifica registros DKIM (assumindo um seletor padrão "default")
        dkim_found, dkim_status = False, "No DKIM record found."
        try:
            dkim_record = 'default._domainkey.' + target
            dkim_records = dns.resolver.resolve(dkim_record, 'TXT')
            for record in dkim_records:
                record_text = str(record)
                if 'v=DKIM1' in record_text:
                    dkim_found = True
                    dkim_status = "DKIM record found and configured."
                    break
        except dns.resolver.NoAnswer:
            dkim_status = "DKIM record missing."
        except dns.resolver.NXDOMAIN:
            dkim_status = "DKIM record not found (NXDOMAIN)."

        # Exibe resultados
        print(f"\nResults for {target}:")
        print(f"SPF Record: {spf_status}")
        print(f"DMARC Record: {dmarc_status}")
        print(f"DKIM Record: {dkim_status}")

        if not (spf_found and dmarc_found and dkim_found):
            print(f"{target} may be vulnerable to Mail Spoofing.")
        else:
            print(f"{target} is protected against Mail Spoofing.")

    except Exception as e:
        print(f"Error checking {target}: {e}")

def main():
    banner()
    target = get_target()
    check_mail_spoofing(target)

if __name__ == "__main__":
    main()
