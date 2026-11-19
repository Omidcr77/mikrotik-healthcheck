"""Offline regression tests: no router required."""
import unittest
import mikrotik_healthcheck as m

class AuditTests(unittest.TestCase):
    def titles(self,d):return [f['title'] for f in m.analyze(d)['findings']]
    def test_counter_array(self):
        self.assertEqual(m.number([123]),123);self.assertIsNone(m.number([1,2]))
    def test_units(self):
        self.assertEqual(m.size_bytes('2GiB'),2147483648);self.assertEqual(m.duration('1d02:03:04'),93784)
    def test_frame_embedded_marker(self):
        value='abc\n@@ROW@@<script>'
        text='@@ROW@@\n@@FIELD@@4:'+str(len(value))+':name'+value+'\n'
        self.assertEqual(m.parse_frames(text),[{'name':value}])
    def test_frame_unicode(self):
        value='???? ????'
        text='@@ROW@@\n@@FIELD@@4:'+str(len(value.encode('utf-8')))+':name'+value+'\n'
        self.assertEqual(m.parse_frames(text),[{'name':value}])
    def test_frame_truncation(self):
        with self.assertRaises(ValueError):m.parse_frames('@@ROW@@\n@@FIELD@@4:100:nameabc')
    def test_classic_flags(self):
        rows=m.parse_detail('Flags: X - DISABLED, R - RUNNING\n 0 R name="ether one" rx-error=0\n 1 X name="ether2" rx-error=2')
        self.assertTrue(rows[0]['running']);self.assertFalse(rows[0]['disabled']);self.assertTrue(rows[1]['disabled'])
    def test_counter_reset_not_negative_rate(self):
        d=m.demo_data();d['ethernet'].rows[0]['rx-bytes']=999999999
        a=m.analyze(d);self.assertEqual(a['rates'],[]);self.assertIn('Counter resets detected',self.titles(d))
    def test_timeout_not_clean_result(self):
        d={'leases':m.Result([],'timeout')}
        self.assertFalse(any('No DHCP' in x for x in m.analyze(d)['checks']))
        self.assertIn('Some checks were unavailable or incomplete',self.titles(d))
    def test_reboot_suppresses_rates(self):
        d=m.demo_data();d['resource_after'].rows[0]['uptime']='2s'
        self.assertEqual(m.analyze(d)['rates'],[])
    def test_arp_separate_interfaces(self):
        d={'arp':m.Result([{'address':'10.0.0.1','interface':'a','mac-address':'AA'}]),'arp_after':m.Result([{'address':'10.0.0.1','interface':'b','mac-address':'BB'}])}
        self.assertNotIn('IP-to-MAC mappings changed',self.titles(d))
    def test_nat_bounded_not_flagged(self):
        d={'nat':m.Result([{'chain':'srcnat','action':'masquerade','src-address':'10.0.0.0/24','out-interface':'WAN'}])}
        self.assertEqual(m.analyze(d)['findings'],[])
    def test_reference_by_id_valid(self):
        d={'hotspots':m.Result([{'name':'a','address-pool':'*1'}]),'pools':m.Result([{'.id':'*1','name':'pool'}])}
        self.assertFalse(any('Unresolved' in x for x in self.titles(d)))
    def test_html_escaping(self):
        d=m.demo_data();d['identity'].rows[0]['name']='<script>alert(1)</script>'
        report={'analysis':m.analyze(d),'host':'test','created_at':'test','coverage':{}}
        out=m.report_html(report)
        self.assertNotIn('<script>alert(1)</script>',out);self.assertIn('&lt;script&gt;',out)
    def test_secrets_scrubbed(self):
        self.assertEqual(m.clean({'private-key':'secret','name':'ok'}),{'name':'ok'})
        self.assertNotIn('abc123',m.clean('password=abc123'))
    def test_quote_routeros(self):
        self.assertEqual(m.ros_quote('x"$y'),r'"x\"\$y"')
    def test_legacy_fallback(self):
        class Fake(m.Reader):
            def __init__(self):super().__init__(None)
            def execute(self,cmd):
                if ':serialize' in cmd:return 'bad command name serialize','unsupported/error','no serialize'
                return '@@ROW@@\n@@FIELD@@4:4:namepool\n','ok',''
        r=Fake();out=r.table('pools')
        self.assertEqual(out.method,'framed');self.assertEqual(out.rows,[{'name':'pool'}]);self.assertFalse(r.json_support)
    def test_truncated_json_never_analyzed(self):
        class Fake(m.Reader):
            def __init__(self):super().__init__(None)
            def execute(self,cmd):return '[{"name":"partial"}]','timeout','timeout'
        out=Fake().table('pools');self.assertEqual(out.rows,[]);self.assertEqual(out.status,'timeout')

if __name__=='__main__':unittest.main()
