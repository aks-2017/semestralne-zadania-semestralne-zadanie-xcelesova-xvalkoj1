import sys
from beautifultable import BeautifulTable


def add_rule(rulesdict):
    source_ip = raw_input('Source IP add: ')
    dest_ip = raw_input('Destination IP add: ')
    action = raw_input('Permit/Deny [P/D]: ')
    protocol = raw_input('IP/ICMP/TCP/UDP/HTTP:')

    key = (source_ip,dest_ip)
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
    table = BeautifulTable()
    if not rulesdict:
        print 'There are not any rules stored'
    else:
        print ('These are our stored rules')
        table.column_headers = ["Source IP", "Destination IP", "Permit/Deny", "Protocol"]
        for key in rulesdict:
            for i in rulesdict[key]:
                table.append_row([key[0], key[1], i[0], i[1]])
        print table

def remove_rule(rulesdict):
    source_ip = raw_input('Source IP add: ')
    dest_ip = raw_input('Destination IP add: ')
    action = raw_input('Permit/Deny [P/D]: ')
    protocol = raw_input('IP/ICMP/TCP/UDP/HTTP:')

    if not source_ip and not dest_ip and not action and not protocol:
        print 'Please specify at least one atribute.'

    elif source_ip and not dest_ip:
        for items in rulesdict.keys():
            if source_ip in items[0]:
                print 'Deleted rule/s '+items[0], items[1], rulesdict[items[0],items[1]]
                del rulesdict[items[0], items[1]]
    elif dest_ip and not source_ip:
        for items in rulesdict.keys():
            if dest_ip in items[1]:
                print 'Deleted rule/s '+items[0], items[1], rulesdict[items[0], items[1]]
                del rulesdict[items[0], items[1]]


def main():
    rulesdict = {}

    #Hard coded data just for info
    key = ('1.1.1.1', '2.2.2.2')
    data = ('P', 'IP')
    rulesdict[key] = [data]

    key = ('1.1.1.1', '2.2.2.2')
    data = ('D', 'UDP')
    rulesdict[key].append(data)

    key = ('192.168.10.3', '100.20.20.2')
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
            remove_rule(rulesdict)
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
