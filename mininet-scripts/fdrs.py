import sys

def add_rule(rulesdict):
    sourceIP = raw_input('Source IP add: ')
    destIP = raw_input('Destination IP add: ')
    action = raw_input('Permit/Deny [P/D]: ')
    protocol = raw_input('IP/ICMP/TCP/UDP/HTTP:')

    key = (sourceIP,destIP)
    data = (action,protocol)

    if key not in rulesdict:
        rulesdict[key] = [data]
        print('\nRule successfully stored\n')
    else:
        print('\nSame rule already exist\n')


def main():
    rulesdict = {}

    while(1):
        prepinac = raw_input('Write required command or -h for help\n')

        if 'h' in prepinac:
            print ('Select from these commands:\n\t-a\tadd rule to firewall\n\t-r\tremove rule from firewall\n\t-s\tshow all rules\n\t-x\texit\n')
        elif 'a' in prepinac:
            print ('Follow guide for adding rules\n')
            add_rule(rulesdict)
        elif 'r' in prepinac:
            print ('No rules to be deleted at this point')
        elif 's' in prepinac:
            print ('These are our stored rules')
        elif 'x' in prepinac:
            print ('Successfully finished')
            sys.exit()
        else:
            print ('WARNING: Unrecognized command\n')


print ('***  ***  ***  ***  ***  ***  ***  ***  ***  ***  ***  ***')
print ('*********************** Firewall *************************')
print ('***  ***  ***  ***  ***  ***  ***  ***  ***  ***  ***  ***\n')

main()
