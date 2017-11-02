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
    elif data not in rulesdict[key]:
        rulesdict[key].append(data)
        print('\nRule successfully stored\n')
    else:
        print('\nSame rule already exist\n')

def show_rule(rulesdict):
    if not rulesdict:
        print 'There are not any rules stored'
    else:
        print ('These are our stored rules\n')
        for key in rulesdict:
            for i in rulesdict[key]:
                print key[0], key[1], i[0], i[1]


def main():
    rulesdict = {}

    #Hard coded data just for info
    key = ('1.1.1.1', '2.2.2.2')
    data = ('P', 'IP')
    rulesdict[key] = [data]

    key = ('1.1.1.1', '2.2.2.2')
    data = ('D', 'UDP')
    rulesdict[key].append(data)

    key = ('3.3.3.3', '4.4.4.4')
    data = ('D', 'HTTP')
    rulesdict[key] = [data]

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
            show_rule(rulesdict)
        elif 'x' in prepinac:
            print ('Successfully finished')
            sys.exit()
        else:
            print ('WARNING: Unrecognized command\n')


print ('***  ***  ***  ***  ***  ***  ***  ***  ***  ***  ***  ***')
print ('*********************** Firewall *************************')
print ('***  ***  ***  ***  ***  ***  ***  ***  ***  ***  ***  ***\n')

main()
