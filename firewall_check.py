
class FirewallCheck(object):
    
    def __init__(self, tables):
        self.tables = tables
        self.src_ips = [ table['dl_src'] for table in tables if 'dl_src' in table]
        self.dst_ips = [ table['dl_dst'] for table in tables if 'dl_dst' in table]
        self.tp_dsts = set([ table['tp_dst'] for table in tables if 'tp_dst' in table])
        self.run_all_checks()

    def run_all_checks(self):
        self.specify_source_ips()
        self.specify_destination_ip()
        self.specify_destination_port()
        self.block_by_default()
        self.allow_specific_traffic()        

    def specify_source_ips(self):
        raise NotImplementedError

    def specify_destination_ip(self):
        raise NotImplementedError

    def specify_destination_port(self):
        raise NotImplementedError

    def block_by_default(self):
        raise NotImplementedError

    def allow_specific_traffic(self):
        raise NotImplementedError


class HttpFirewallCheck(FirewallCheck):

    def __init__(self, table):
        super().__init__(table)

    def block_by_default(self):
        # assert that there is a catch-all block to drop anything else
        for table in tables:
            if 'dl_src' not in table:
                assert(table['actions'] == 'ANY')
        print("block_by_default check passed")

    def allow_specific_traffic(self):
        # assert that there exists an entry in tables that will allow port 80 traffic
        for table in tables:
            if ('tp_dst' in table and table['tp_dst'] == 80):
                assert(table['dl_dst'])
                assert(table['dl_src'])
                assert(table['actions'] == 'NORMAL')
        print("allow_specific_traffic check passed")
    
    def specify_source_ips(self):
        # assert that source IPs have been specified in the tables
        print(self.src_ips)
        assert(self.src_ips)
        print("specify_source_ips check passed")

    def specify_destination_ip(self):
        # assert that destination IPs have been specified in the tables
        assert(self.dst_ips)
        print("specify_destination_ip check passed")

    def specify_destination_port(self):
        # assert that port 80 is the only port with a NORMAL entry
        assert(set([80]) == self.tp_dsts)
        assert(len(self.tp_dsts) == 1)
        for table in tables:
            if 'dl_src' in table and 'dl_dst' in table and 'tp_dst' in table and table['tp_dst'] == 80 and 'actions' in table:
                assert(table['actions'] == "NORMAL")
        print("specify_destination_port check passed")

if __name__=='__main__':
    tables = [{'dl_src':'10.0.0.1', 'dl_dst':'10.0.0.2', 'tp_dst': 80, 'actions':'NORMAL'},
              {'dl_src':'10.0.0.2', 'dl_dst':'10.0.0.1', 'tp_dst': 80, 'actions':'NORMAL'},
              {'actions':'ANY'}]
    f1 = HttpFirewallCheck(tables)
