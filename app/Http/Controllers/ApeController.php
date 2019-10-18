<?php

namespace App\Http\Controllers;

use Cookie;
use Storage;
use Response;
use Parsedown;
use phpWhois\Whois;
use Net_DNS2_Resolver;
use Illuminate\Http\Request;
use Symfony\Component\Process\Process;
use Symfony\Component\Process\Exception\ProcessFailedException;

class ApeController extends Controller
{

    private $cacheServers = [
        "Cloudflare" => ["1.1.1.1"],
        "Google" => ["8.8.8.8","8.8.4.4"],
        "OpenDNS" => ["208.67.222.222","208.67.220.220"],
        "Level3" => ["4.2.2.1","4.2.2.2","4.2.2.3","4.2.2.4"],
        "Comodo" => ["8.26.56.26"],
        "DNS Watch" => ["84.200.69.80"],
        "Verisign" => ["64.6.64.6"],
        "EarthLink" => ["207.69.188.185"],
        "CenturyLink" => ["205.171.3.65"],
    ];

    public function __construct() {
    }

    function dns(Request $request) {
        $resolver = new Net_DNS2_Resolver(array('nameservers' => array('1.1.1.1','208.67.222.222','8.8.8.8','4.2.2.1')));

        // PTR records
        try {
            $reverseip = implode('.', array_reverse(explode('.', GetHostByName($request->host))));
            $ptrlookup = $reverseip.".in-addr.arpa";
            $response = $resolver->query($ptrlookup, 'PTR');
            $i=0;
            if(count($response->answer) > 0) {
                foreach ($response->answer as $rr) {
                    $ptr[$i]['answer_from'] = $response->answer_from;
                    $ptr[$i]['ptrdname'] = $rr->ptrdname;
                    $ptr[$i]['name'] = $rr->name;
                    $ptr[$i]['type'] = $rr->type;
                    $ptr[$i]['ttl'] = $rr->ttl;
                    $ptr[$i]['response'] = 1;
                    $i++;
                }
            }
        } catch(\Net_DNS2_Exception $e) {
            $ptr[0]['ptrdname'] = $request->host;
            $ptr[0]['response'] = 0;
        }

        // NS records
        try {
            $response = $resolver->query($request->host, 'NS');
        } catch(\Net_DNS2_Exception $e) {
            $ns[0]['message'] = $e->getMessage();
            $ns[0]['name'] = $request->host;
            $ns[0]['response'] = 0;
            exit("<br/><b>".$request->host."</b> ".$ns[0]['message']."<br/><br/>");
        }
        $i=0;
        if (isset($response)) {
            if(count($response->answer) > 0) {
                foreach ($response->answer as $rr) {
                    if ($rr->type == 'NS') {
                        $ns[$i]['answer_from'] = $response->answer_from;
                        $ns[$i]['nsdname'] = $rr->nsdname;
                        $ns[$i]['name'] = $rr->name;
                        $ns[$i]['type'] = $rr->type;
                        $ns[$i]['ttl'] = $rr->ttl;
                        $ns[$i]['response'] = 1;
                        $i++;
                    }
                }
            }
        }
        if(!isset($ns)) {
            $ns[0]['name'] = $request->host;
            $ns[0]['response'] = 0;
        }

        // A records
        $response = $resolver->query($request->host, 'A');
        if ($response) {
            $i=0;
            if(count($response->answer) > 0) {
                foreach ($response->answer as $rr) {
                    if ($rr->type == 'A') {
                        $a[$i]['answer_from'] = $response->answer_from;
                        $a[$i]['address'] = $rr->address;
                        $a[$i]['name'] = $rr->name;
                        $a[$i]['type'] = $rr->type;
                        $a[$i]['ttl'] = $rr->ttl;
                        $a[$i]['response'] = 1;
                        $i++;
                    }
                }
            } else {
                $a=0;
            }
        }

        // AAAA records
        $response = $resolver->query($request->host, 'AAAA');
        if ($response) {
            $i=0;
            if(count($response->answer) > 0) {
                foreach ($response->answer as $rr) {
                    if ($rr->type == 'AAAA') {
                        $aaaa[$i]['answer_from'] = $response->answer_from;
                        $aaaa[$i]['address'] = $rr->address;
                        $aaaa[$i]['name'] = $rr->name;
                        $aaaa[$i]['type'] = $rr->type;
                        $aaaa[$i]['ttl'] = $rr->ttl;
                        $aaaa[$i]['response'] = 1;
                        $i++;
                    }
                }
            }
            if($i==0) {
                $aaaa=0;
            }
        }

        // CNAME records
        try {
            $response = $resolver->query($request->host, 'CNAME');
        } catch (Net_DNS2_Exception $e) {
            echo "::query() failed: ", $e->getMessage(), "\n";
        }
        if ($response) {
            $i=0;
            if(count($response->answer) > 0) {
                foreach ($response->answer as $rr) {
                    $cnames[$i]['answer_from'] = $response->answer_from;
                    $cnames[$i]['cname'] = $rr->cname;
                    $cnames[$i]['name'] = $rr->name;
                    $cnames[$i]['type'] = $rr->type;
                    $cnames[$i]['ttl'] = $rr->ttl;
                    $cnames[$i]['response'] = 1;
                    $i++;
                }
            } else {
                $cnames=0;
            }
        }

        // MX mail records
        try {
            $response = $resolver->query($request->host, 'MX');
            $i=0;
            if(count($response->answer) > 0) {
                foreach ($response->answer as $rr) {
                    if ($rr->type == 'MX') {
                        $mxrecs[$i]['answer_from'] = $response->answer_from;
                        $mxrecs[$i]['preference'] = $rr->preference;
                        $mxrecs[$i]['exchange'] = $rr->exchange;
                        $mxrecs[$i]['name'] = $rr->name;
                        $mxrecs[$i]['type'] = $rr->type;
                        $mxrecs[$i]['ttl'] = $rr->ttl;
                        $mxrecs[$i]['response'] = 1;
                        $i++;
                    }
                }
            }
            if(!isset($mxrecs)) {
                $mxrecs[0]['name'] = $request->host;
                $mxrecs[0]['response'] = 0;
            }
        } catch(\NetDNS2_Exception $e) {
            $mxrecs[0]['name'] = $request->host;
            $mxrecs[0]['response'] = 0;
        }

        // TXT mail records
        try {
            $response = $resolver->query($request->host, 'TXT');
            $i=0;
            if(count($response->answer) > 0) {
                foreach ($response->answer as $rr) {
                    if ($rr->type == 'TXT') {
                        $txtrecs[$i]['answer_from'] = $response->answer_from;
                        $txtrecs[$i]['rdata'] = $rr->rdata;
                        $txtrecs[$i]['name'] = $rr->name;
                        $txtrecs[$i]['type'] = $rr->type;
                        $txtrecs[$i]['ttl'] = $rr->ttl;
                        $txtrecs[$i]['response'] = 1;
                        $i++;
                    }
                }
            }
            if(!isset($txtrecs)) {
                $txtrecs[0]['name'] = $request->host;
                $txtrecs[0]['response'] = 0;
            }
        } catch(\NetDNS2_Exception $e) {
            $txtrecs[0]['name'] = $request->host;
            $txtrecs[0]['response'] = 0;
        }

        // SPF mail records
        try {
            $response = $resolver->query($request->host, 'SPF');
            $i=0;
            if(count($response->answer) > 0) {
                foreach ($response->answer as $rr) {
                    if ($rr->type == 'SPF') {
                        $spfrecs[$i]['answer_from'] = $response->answer_from;
                        $spfrecs[$i]['rdata'] = $rr->rdata;
                        $spfrecs[$i]['name'] = $rr->name;
                        $spfrecs[$i]['type'] = $rr->type;
                        $spfrecs[$i]['ttl'] = $rr->ttl;
                        $spfrecs[$i]['response'] = 1;
                        $i++;
                    }
                }
            }
            if(!isset($spfrecs)) {
                $spfrecs[0]['name'] = $request->host;
                $spfrecs[0]['response'] = 0;
            }
        } catch(\NetDNS2_Exception $e) {
            $spfrecs[0]['name'] = $request->host;
            $spfrecs[0]['response'] = 0;
        }

        // SRV mail records
        try {
            $response = $resolver->query($request->host, 'SRV');
            $i=0;
            if(count($response->answer) > 0) {
                foreach ($response->answer as $rr) {
                    if ($rr->type == 'SRV') {
                        $srvrecs[$i]['answer_from'] = $response->answer_from;
                        $srvrecs[$i]['rdata'] = $rr->rdata;
                        $srvrecs[$i]['name'] = $rr->name;
                        $srvrecs[$i]['type'] = $rr->type;
                        $srvrecs[$i]['ttl'] = $rr->ttl;
                        $srvrecs[$i]['response'] = 1;
                        $i++;
                    }
                }
            }
            if(!isset($srvrecs)) {
                $srvrecs[0]['name'] = $request->host;
                $srvrecs[0]['response'] = 0;
            }
        } catch(\NetDNS2_Exception $e) {
            $srvrecs[0]['name'] = $request->host;
            $srvrecs[0]['response'] = 0;
        }

        // SOA mail records
        try {
            $response = $resolver->query($request->host, 'SOA');
            $i=0;
            if(count($response->answer) > 0) {
                foreach ($response->answer as $rr) {
                    if ($rr->type == 'SOA') {
                        $pos = strpos($rr->rname, ".");
                        if ($pos !== false) {
                            $rname = substr_replace($rr->rname, "@", $pos, strlen("."));
                        }
                        $soarecs[$i]['answer_from'] = $response->answer_from;
                        $soarecs[$i]['mname'] = $rr->mname;
                        $soarecs[$i]['rname'] = $rname;
                        $soarecs[$i]['serial'] = $rr->serial;
                        $soarecs[$i]['refresh'] = $rr->refresh;
                        $soarecs[$i]['retry'] = $rr->retry;
                        $soarecs[$i]['expire'] = $rr->expire;
                        $soarecs[$i]['minimum'] = $rr->minimum;
                        $soarecs[$i]['name'] = $rr->name;
                        $soarecs[$i]['rdata'] = $rr->rdata;
                        $soarecs[$i]['type'] = $rr->type;
                        $soarecs[$i]['ttl'] = $rr->ttl;
                        $soarecs[$i]['response'] = 1;
                        $i++;
                    }
                }
            }
            if(!isset($soarecs)) {
                $soarecs[0]['name'] = $request->host;
                $soarecs[0]['response'] = 0;
            }
        } catch(\NetDNS2_Exception $e) {
            $soarecs[0]['name'] = $request->host;
            $soarecs[0]['response'] = 0;
        }

        return view('dns', [
            'ptrrecs' => $ptr,
            'nameservers' => $ns,
            'arecs' => $a,
            'aaaarecs' => $aaaa,
            'cnames' => $cnames,
            'mxrecs' => $mxrecs,
            'txtrecs' => $txtrecs,
            'spfrecs' => $spfrecs,
            'srvrecs' => $srvrecs,
            'soarecs' => $soarecs
        ]);
    }

    function traversal(Request $request) {
        $domain = $request->host;
        $recordType = $request->record;
        $tldHosts = $this->getTLDHosts($request->host);
        $resolver = new Net_DNS2_Resolver();
        $resolver->usevc = 1;
        $authServers = array();
        foreach($tldHosts as $gtldhost => $gtldip) {
            $resolver->nameservers = array($gtldip);
            try {
                $response = $resolver->query($domain, 'NS');
            } catch(\Net_DNS2_Exception $e) {
                $ns[0]['message'] = $e->getMessage();
                $ns[0]['name'] = $request->host;
                $ns[0]['response'] = 0;
                exit("<br/><b>".$request->host."</b> ".$ns[0]['message']."<br/><br/>");
            }
            if ($response) {
                foreach ($response->authority as $rr) {
                    $authNS = $rr->nsdname;
                    if(!in_array($authNS, $authServers)) {
                        $authServers[] = $rr->nsdname;
                    }
                }
            }
        }
        echo "<pre>\n\n";
        echo "<b>Authoritative servers</b><br/>";
        foreach($authServers as $server) {
            $ip = gethostbyname($server);
            if($recordType == 'PTR') {
                $reverseip = implode('.', array_reverse(explode('.', GetHostByName($request->host))));
                $domain = $reverseip.".in-addr.arpa";
            }
            $resolver->nameservers = array($ip);
            try {
                $response = $resolver->query($domain, $recordType);
            } catch(\Net_DNS2_Exception $e) {
                echo $e->getMessage()."<br/>";
            }
            if($recordType == 'SOA') {
                foreach ($response->answer as $rr) {
                    if($rr->type == "SOA") {
                        $pos = strpos($rr->rname, ".");
                        if ($pos !== false) {
                            $rname = substr_replace($rr->rname, "@", $pos, strlen("."));
                        }
                    }
                }
            }
            echo "<br/>Response from <b>$server</b> ($ip):<br />";
            if(empty($response->answer)) {
                echo "No records returned.<br/>";
            }
            if ($response) {
                foreach ($response->answer as $rr) {
                    if($recordType == $rr->type) {
                        switch($rr->type) {
                            case 'A':
                                if($rr->type == "A") {
                                    echo $rr->address."<br/>";
                                } else {
                                    echo "No A records returned<br/>";
                                }
                                break;
                            case 'AAAA':
                                if($rr->type == "AAAA") {
                                    echo $rr->address."<br/>";
                                } else {
                                    echo "No AAAA records returned<br/>";
                                }
                                break;
                            case 'PTR':
                                if($rr->type == "PTR") {
                                    echo $rr->ptrdname."<br/>";
                                } else {
                                    echo "No PTR records returned<br/>";
                                }
                                break;
                            case 'NS':
                                if($rr->type == "NS") {
                                    echo $rr->nsdname."<br/>";
                                } else {
                                    echo "No NS records returned<br/>";
                                }
                                break;
                            case 'CNAME':
                                if($rr->type == "CNAME") {
                                    echo $rr->cname."<br/>";
                                } else {
                                    echo "No CNAME records returned<br/>";
                                }
                                break;
                            case 'MX':
                                if($rr->type == "MX") {
                                    echo "MX".$rr->preference." ".$rr->exchange."<br/>";
                                } else {
                                    echo "No MX records returned<br/>";
                                }
                                break;
                            case 'TXT':
                                if($rr->type == "TXT") {
                                    echo $rr->rdata."<br/>";
                                } else {
                                    echo "No TXT records returned<br/>";
                                }
                                break;
                            case 'SPF':
                                if($rr->type == "SPF") {
                                    echo $rr->rdata."<br/>";
                                } else {
                                    echo "No SPF records returned<br/>";
                                }
                                break;
                            case 'SRV':
                                if($rr->type == "SRV") {
                                    echo $rr->rdata."<br/>";
                                } else {
                                    echo "No SRV records returned<br/>";
                                }
                                break;
                            case 'SOA':
                                if($rr->type == "SOA") {
                                    echo "Primary NS: ".$rr->mname."<br/>";
                                    echo "Responsible party: <a href=\"mailto:$rname\">".$rname."</a><br/>";
                                    echo "Serial: ".$rr->serial."<br/>";
                                    echo "Refresh: ".$rr->refresh."<br/>";
                                    echo "Retry: ".$rr->retry."<br/>";
                                    echo "Minimum: ".$rr->minimum."<br/>";
                                    echo "Expire: ".$rr->expire."<br/>";
                                } else {
                                    echo "No SOA records returned<br/>";
                                }
                                break;
                        }
                    }
                }
            }
        }
        $authServers = array();
        echo "<hr/><b>Top level domain servers</b><br/><br/>";
        foreach($tldHosts as $gtldhost => $gtldip) {
            $resolver->nameservers = array($gtldip);
            $response = $resolver->query($domain, 'NS');
            if ($response) {
                echo "Response from <b>$gtldhost</b> ($gtldip):<br />";
                foreach ($response->authority as $rr) {
                    echo $rr->nsdname."<br/>";
                    $authNS = $rr->nsdname;
                    if(!in_array($authNS, $authServers)) {
                        $authServers[] = $rr->nsdname;
                    }
                }
            }
        }
        echo "<hr/><b>Root servers</b><br/><br/>";
        $rootServers = $this->getTLDHosts(".");
        foreach($rootServers as $server=>$ip) {
            $resolver->nameservers = array($ip);
            $response = $resolver->query($domain, 'NS');
            if ($response) {
                echo "Response from <b>$server</b> ($ip):<br />";
                foreach ($response->authority as $rr) {
                    echo $rr->nsdname."<br/>";
                }
            }
        }
        echo "</pre>";
    }

    function cache(Request $request) {
        $domain = $request->host;
        $recordType = $request->record;
        $resolver = new Net_DNS2_Resolver();
        $resolver->usevc = 1;
        $i=0;
        foreach($this->cacheServers as $server=>$ips) {
            foreach($ips as $ip) {
                $resolver->nameservers = array($ip);
                if($recordType == 'PTR') {
                    $reverseip = implode('.', array_reverse(explode('.', GetHostByName($request->host))));
                    $domain = $reverseip.".in-addr.arpa";
                }
                try {
                    $response = $resolver->query($domain, $request->record);
                } catch(\Net_DNS2_Exception $e) {
                    $ns[0]['message'] = $e->getMessage();
                    $ns[0]['name'] = $request->host;
                    $ns[0]['response'] = 0;
                    exit("<br/><b>".$request->host."</b> ".$ns[0]['message']."<br/><br/>");
                }
                if($recordType == 'SOA') {
                    foreach ($response->answer as $rr) {
                        $pos = strpos($rr->rname, ".");
                        if ($pos !== false) {
                            $rname = substr_replace($rr->rname, "@", $pos, strlen("."));
                        }
                    }
                }
                if ($response) {
                    if($i==0) {
                        echo "<pre>";
                    }
                    echo "<br/>Response from <b>$server</b> ($ip):<br />";
                    if(empty($response->answer)) {
                        echo "No records returned.<br/>";
                    }
                    foreach ($response->answer as $rr) {
                        if($recordType == $rr->type) {
                            switch($rr->type) {
                                case 'A':
                                    if($rr->type == "A") {
                                        echo $rr->address."<br/>";
                                    } else {
                                        echo "No A records returned<br/>";
                                    }
                                    break;
                                case 'AAAA':
                                    if($rr->type == "AAAA") {
                                        echo $rr->address."<br/>";
                                    } else {
                                        echo "No AAAA records returned<br/>";
                                    }
                                    break;
                                case 'PTR':
                                    if($rr->type == "PTR") {
                                        echo $rr->ptrdname."<br/>";
                                    } else {
                                        echo "No PTR records returned<br/>";
                                    }
                                    break;
                                case 'NS':
                                    if($rr->type == "NS") {
                                        echo $rr->nsdname."<br/>";
                                    } else {
                                        echo "No NS records returned<br/>";
                                    }
                                    break;
                                case 'CNAME':
                                    if($rr->type == "CNAME") {
                                        echo $rr->cname."<br/>";
                                    } else {
                                        echo "No CNAME records returned<br/>";
                                    }
                                    break;
                                case 'MX':
                                    if($rr->type == "MX") {
                                        echo "MX".$rr->preference." ".$rr->exchange."<br/>";
                                    } else {
                                        echo "No MX records returned<br/>";
                                    }
                                    break;
                                case 'TXT':
                                    if($rr->type == "TXT") {
                                        echo $rr->rdata."<br/>";
                                    } else {
                                        echo "No TXT records returned<br/>";
                                    }
                                    break;
                                case 'SPF':
                                    if($rr->type == "SPF") {
                                        echo $rr->rdata."<br/>";
                                    } else {
                                        echo "No SPF records returned<br/>";
                                    }
                                    break;
                                case 'SRV':
                                    if($rr->type == "SRV") {
                                        echo $rr->rdata."<br/>";
                                    } else {
                                        echo "No SRV records returned<br/>";
                                    }
                                    if(isset($rr->rdata)) {
                                        $recordExists=1;
                                    }
                                    break;
                                case 'SOA':
                                    if($rr->type == "SOA") {
                                        echo "Primary NS: ".$rr->mname."<br/>";
                                        echo "Responsible party: <a href=\"mailto:$rname\">".$rname."</a><br/>";
                                        echo "Serial: ".$rr->serial."<br/>";
                                        echo "Refresh: ".$rr->refresh."<br/>";
                                        echo "Retry: ".$rr->retry."<br/>";
                                        echo "Minimum: ".$rr->minimum."<br/>";
                                        echo "Expire: ".$rr->expire."<br/>";
                                    } else {
                                        echo "No SOA records returned<br/>";
                                    }
                                    break;
                                default:
                            }
                        }
                    }
                }
            }
            $i++;
        }
        echo "</pre>";
    }

    function getTLDHosts($domain) {
        if($domain == ".") {
            $process = new Process("dig -t ns ".$domain."|grep root|awk '{print $5}'");
        } else {
			$domain = $this->getTopLevelDomain($domain);
            $process = new Process("dig -t ns ".$domain.".|grep '^".$domain."'|awk '{print $5}'");
        }
        try {
            $process->mustRun();
            $tlds[] = $process->getOutput();
        } catch (ProcessFailedException $e) {
            echo $e->getMessage();
        }
        $tlds = array_filter($tlds);
        foreach($tlds as $tld) {
            $tldList = array_filter(explode("\n", $tld));
        }
        if(!isset($tldList)) {
            exit("<br/>Unable to get TLD hosts, please try again...<br/><br/>");
        } else {
            foreach($tldList as $tldHost) {
                $tldHosts[$tldHost] = gethostbyname($tldHost);
            }
        }
        return $tldHosts;
    }

	function getTopLevelDomain($url){
        $url = "http://".$url;
		$urlData = parse_url($url);
		$urlHost = isset($urlData['host']) ? $urlData['host'] : '';
		$isIP = (bool)ip2long($urlHost);
		if($isIP){ /** To check if it's ip then return same ip */
			return $urlHost;
		}
		/** Add/Edit you TLDs here */
		$suffixArray = explode("\n", Storage::get('suffixes.dat'));
		foreach($suffixArray as $suffix) {
            if(substr($suffix, 0, 2) !== '//' && $suffix !=null) {
                $urlMap[] = $suffix;
            }
		}

		$host = "";
		$hostData = explode('.', $urlHost);
		if(isset($hostData[1])){ /** To check "localhost" because it'll be without any TLDs */
			$hostData = array_reverse($hostData);

			if(array_search($hostData[1] . '.' . $hostData[0], $urlMap) !== FALSE) {
				$host = $hostData[1] . '.' . $hostData[0];
			} elseif(array_search($hostData[0], $urlMap) !== FALSE) {
				$host = $hostData[0];
			}
			return $host;
		}
		return ((isset($hostData[0]) && $hostData[0] != '') ? $hostData[0] : 'Error: no matching TLD found for ' . $urlHost);
	}

	function getSecondLevelDomain($url){
        $url = "http://".$url;
		$urlData = parse_url($url);
		$urlHost = isset($urlData['host']) ? $urlData['host'] : '';
		$isIP = (bool)ip2long($urlHost);
		if($isIP) {
			exit("Please provide a domain for Whois lookup.");
		}
		/** Add/Edit you TLDs here */
		$suffixArray = explode("\n", Storage::get('suffixes.dat'));
		foreach($suffixArray as $suffix) {
            if(substr($suffix, 0, 2) !== '//' && $suffix !=null) {
                $urlMap[] = $suffix;
            }
		}

		$host = "";
		$hostData = explode('.', $urlHost);
		if(isset($hostData[1])){ /** To check "localhost" because it'll be without any TLDs */
			$hostData = array_reverse($hostData);

			if(array_search($hostData[1] . '.' . $hostData[0], $urlMap) !== FALSE) {
				$host = $hostData[2] . '.' . $hostData[1] . '.' . $hostData[0];
			} elseif(array_search($hostData[0], $urlMap) !== FALSE) {
				$host = $hostData[1] . '.' . $hostData[0];
			}
			return $host;
		}
		return ((isset($hostData[0]) && $hostData[0] != '') ? $hostData[0] : 'Error: no matching TLD found for ' . $urlHost);
	}

    function getHeaders($URL) {
        $ssl="";
        if(strpos($URL,'s',4)) {
            $ssl = "ssl://";
            $port = 443;
            if (substr_count(strtolower($URL), "https://") == 0) { 
                $URL = "https://".$URL;
            }    
        } else {
            if (substr_count(strtolower($URL), "http://") == 0) { 
                $URL = "http://".$URL;
            }    
            $port = 80;
        }
        $DomainInfo = @parse_url($URL);
        $Path = (isset($DomainInfo['path'])) ? $DomainInfo['path'] : '/';
        if ($Path == "") $Path = "/";
        $Headers  = "GET ".$Path." HTTP/1.1\r\n";
        $Headers .= "Accept: */*\r\n";
        $Headers .= "Accept-Language: en-us\r\n";
        $Headers .= "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:64.0) Gecko/20100101 Firefox/64.0\r\n";
        $Headers .= "Host: ".$DomainInfo['host']."\r\n";
        $Headers .= "Connection: close\r\n\r\n";
        $SocketHandle = @fsockopen($ssl.$DomainInfo['host'], $port, $ErrorNumber, $ErrorMessage, 2);
        if ($SocketHandle == FALSE) {
            return FALSE;
        }
        fputs($SocketHandle, $Headers);
        $ResponseHeaders = "";
        while (feof($SocketHandle) == FALSE) {    
            $ResponseHeaders .= fgets($SocketHandle, 4096);
            if (strstr($ResponseHeaders, "\r\n\r\n"))
            break;
        }
        return $ResponseHeaders;
    }

    function httpHeaders(Request $request) {
        $Text = "<pre>\r\n\r\n";
        $Location = $request->host;
        $PageLocation = $Location;
        while($Location != "") {
            $Headers = $this->getHeaders($Location);
            $Token = strtok($Headers, "\r\n");
            while($Token) {
                $Text .= $this->formatHeaderText($Token, "\r")."<br>";
                $Token = strtok("\r\n");
            }
            $Text .= "<br>";
            $Location = $this->getHeaderParameter($Headers, "Location: ");
            if ($Location != "") {
                $PageLocation = $this->buildURL($PageLocation, $Location);
                $Text .= "<b>Redirecting to <a href=\"".$PageLocation."\">".$PageLocation."</a></b><br><br>";
            }
        }
        $Text .= "</pre>";
        return $Text;
    }

    function formatHeaderText($Text, $Break, $Cut = "\r\n", $Length = '82', $Shorten = '') {
        $ReturnText = "";
        $Wrap = $Text;
        while (strlen($Wrap) > $Length) {
            $PartWrap = substr($Wrap, 0, $Length);
            if ($Shorten != "") {
                $ReturnText .= substr($PartWrap, 0, $Length - strlen($Shorten));
                $ReturnText .= $Shorten;
                return $ReturnText;
            }
            if ($Break != "") {
                $LastBreak = strrpos($PartWrap, $Break);
            } else {
                $LastBreak = $Length;
            }
            if ($LastBreak !== FALSE) {
                $LastBreak += strlen($Break);
                $PartWrap = substr($Wrap, 0, $LastBreak);
            } else {
                $LastBreak = $Length;
            }
            $ReturnText .= $PartWrap.$Cut;
            $Wrap = substr($Wrap, $LastBreak);
        }
        $ReturnText .= $Wrap;
        return $ReturnText;
    }

    function getHeaderParameter($Header, $Parameter) {
        $ParameterStart = strpos($Header, $Parameter);
        if ($ParameterStart !== FALSE) {
            $ParameterString = substr($Header, $ParameterStart);
            $ParameterEnd = strpos($ParameterString, "\r\n") - strlen($Parameter);
            return substr($ParameterString, strlen($Parameter), $ParameterEnd);
        }
        return FALSE;
    }

    function buildURL($FullURL, $PartURL) {
        $PartURL = str_replace("\"", "", $PartURL);
        $PartURL = str_replace("'", "", $PartURL);
        $PartURL = str_replace("&amp;", "&", $PartURL);
        $FullURL = str_replace("\"", "", $FullURL);
        $FullURL = str_replace("'", "", $FullURL);
        $FullURL = str_replace("&amp;", "&", $FullURL);
        if (strpos($PartURL, "?http://") == 0 && strpos($PartURL, "?http") !== FALSE) {
            $PartURL = substr($PartURL, 1);
            if (strpos($PartURL, "?") === FALSE) {
                $PartURL = substr($PartURL, 0, strpos($PartURL, "&&"))."?".substr($PartURL, strpos($PartURL, "&&"));
            }
            $PartURL = str_replace(".com?", ".com/?", $PartURL);
        }
        if (strpos($PartURL, "http://") == 0 && strpos($PartURL, "http://") !== FALSE) {
            return $PartURL;
        }
        if (strpos($PartURL, "https://") == 0 && strpos($PartURL, "https://") !== FALSE) {
            return $PartURL;
        }
        if (substr_count($FullURL, "/") == 2) {
            $FullURL = $FullURL."/";
        }
        $LastPath = substr($FullURL, 0, strrpos($FullURL, "/") + 1);
        if ($PartURL[0] == '/') {
            $LastPath = substr($LastPath, 0, strpos($LastPath, "/", 9));
        }
        if ($LastPath[strlen($LastPath) - 1] == '/' && $PartURL[0] == '/') {
            $PartURL = substr($PartURL, 1);
        }
        return $LastPath.$PartURL;
    }

    function whois(Request $request) {
        $whois = new Whois();
        $whois->deepWhois = true;
        $sld = $this->getSecondLevelDomain($request->host);
        $result = $whois->lookup($sld, false);
        echo "<br/><pre>";
        if($result['regrinfo']['registered'] === "yes" || isset($result['regrinfo']['domain']['status'])) {
            if(isset($result['regrinfo']['domain']['expires'])) {
                echo "$sld expires on ".$result['regrinfo']['domain']['expires']."<br/><br/>";
            }
            foreach($result['rawdata'] as $data) {
                echo rtrim($data)."\r";
            }
        } elseif($result['regrinfo']['registered'] === "no" && !isset($result['regrinfo']['domain']['status'])) {
            echo "<br/><b>$sld</b> is not registered, lucky you!<br/><br/>";
            return;
        }
        echo "</pre>";
    }

    function ipwhois(Request $request) {
        $whois = new Whois();
        // if we're using a FQDN, resolve IP from host name
        // if IS and IP address
        // else resolve domain name
        if($this->isValidHost($request->host)) {
            $ip = gethostbyname($request->host);
            $result = $whois->lookup($ip, false);
            if ($ip == $request->host) {
                echo "<br/><b>" . htmlspecialchars($ip,ENT_QUOTES) . "</b> couldn't be resolved.<br/><br/>";
            } else {
                echo "<pre>";
                foreach($result['rawdata'] as $data) {
                    echo $data."<br/>";
                }
                echo "</pre>";
            }
        } elseif($this->isValidIP($request->host)) {
            $result = $whois->lookup($request->host, false);
            echo "<pre>";
            foreach($result['rawdata'] as $data) {
                echo $data."<br/>";
            }
            echo "</pre>";
        } else {
            echo "<br/><b>$request->host</b> couldn't be resolved.<br/><br/>";
        }
    }

    function rbl(Request $request) {

        $rbls = [
            'b.barracudacentral.org',
            'cbl.abuseat.org',
            'http.dnsbl.sorbs.net',
            'misc.dnsbl.sorbs.net',
            'socks.dnsbl.sorbs.net',
            'web.dnsbl.sorbs.net',
            'dnsbl-1.uceprotect.net',
            'dnsbl-3.uceprotect.net',
            'sbl.spamhaus.org',
            'zen.spamhaus.org',
            'psbl.surriel.com',
            'rbl.spamlab.com',
            'noptr.spamrats.com',
            'cbl.anti-spam.org.cn',
            'dnsbl.inps.de',
            'httpbl.abuse.ch',
            'korea.services.net',
            'virus.rbl.jp',
            'wormrbl.imp.ch',
            'rbl.suresupport.com',
            'ips.backscatterer.org',
            'opm.tornevall.org',
            'multi.surbl.org',
            'tor.dan.me.uk',
            'relays.mail-abuse.org',
            'rbl-plus.mail-abuse.org',
            'access.redhawk.org',
            'rbl.interserver.net',
            'bogons.cymru.com',
            'bl.spamcop.net',
            'dnsbl.sorbs.net',
            'dul.dnsbl.sorbs.net',
            'smtp.dnsbl.sorbs.net',
            'spam.dnsbl.sorbs.net',
            'zombie.dnsbl.sorbs.net',
            'dnsbl-2.uceprotect.net',
            'pbl.spamhaus.org',
            'xbl.spamhaus.org',
            'bl.spamcannibal.org',
            'ubl.unsubscore.com',
            'dyna.spamrats.com',
            'spam.spamrats.com',
            'cdl.anti-spam.org.cn',
            'drone.abuse.ch',
            'dul.ru',
            'short.rbl.jp',
            'spamrbl.imp.ch',
            'virbl.bit.nl',
            'dsn.rfc-ignorant.org',
            'dsn.rfc-ignorant.org',
            'netblock.pedantic.org',
            'ix.dnsbl.manitu.net',
            'rbl.efnetrbl.org',
            'blackholes.mail-abuse.org',
            'dnsbl.dronebl.org',
            'db.wpbl.info',
            'query.senderbase.org',
            'bl.emailbasura.org',
            'combined.rbl.msrbl.net',
            'ff.uribl.com',
            'cblless.anti-spam.org.cn',
            'cblplus.anti-spam.org.cn',
            'blackholes.five-ten-sg.com',
            'sorbs.dnsbl.net.au',
            'rmst.dnsbl.net.au',
            'dnsbl.kempt.net',
            'blacklist.woody.ch',
            'rot.blackhole.cantv.net',
            'virus.rbl.msrbl.net',
            'phishing.rbl.msrbl.net',
            'images.rbl.msrbl.net',
            'spam.rbl.msrbl.net',
            'spamlist.or.kr',
            'dnsbl.abuse.ch',
            'bl.deadbeef.com',
            'ricn.dnsbl.net.au',
            'forbidden.icm.edu.pl',
            'probes.dnsbl.net.au',
            'ubl.lashback.com',
            'ksi.dnsbl.net.au',
            'uribl.swinog.ch',
            'bsb.spamlookup.net',
            'dob.sibl.support-intelligence.net',
            'url.rbl.jp',
            'dyndns.rbl.jp',
            'omrs.dnsbl.net.au',
            'osrs.dnsbl.net.au',
            'orvedb.aupads.org',
            'relays.nether.net',
            'relays.bl.gweep.ca',
            'relays.bl.kundenserver.de',
            'dialups.mail-abuse.org',
            'rdts.dnsbl.net.au',
            'duinv.aupads.org',
            'dynablock.sorbs.net',
            'residential.block.transip.nl',
            'dynip.rothen.com',
            'dul.blackhole.cantv.net',
            'mail.people.it',
            'blacklist.sci.kun.nl',
            'all.spamblock.unit.liu.se',
            'spamguard.leadmon.net',
            'csi.cloudmark.com',
        ];

        $ip          = $request->host;
        $rev         = join('.', array_reverse(explode('.', trim($ip))));
        $i           = 1;
        $rbl_count   = count($rbls);
        $listed_rbls = [];
        echo "<br/>";

        foreach ($rbls as $rbl)
        {
            printf('Checking %s, %d of %d... ', $rbl, $i, $rbl_count);
            $lookup = sprintf('%s.%s', $rev, $rbl);

            $listed = gethostbyname($lookup) !== $lookup;

            printf('[%s]%s', $listed ? 'LISTED' : 'OK', PHP_EOL);

            if ( $listed )
            {
                $listed_rbls[] = $rbl;
            }
            echo "<br/>";
            $i++;
        }

        printf('<br/>%s listed on %d of %d known blacklists%s.<br/><br/>', $ip, count($listed_rbls), $rbl_count, PHP_EOL);

        if ( ! empty($listed_rbls) )
        {
            printf('%s listed on %s%s', $ip, join(', ', $listed_rbls), PHP_EOL);
        }
    }

    function ssl(Request $request) {
        $domain = $request->host;
        if($this->isValidHost($request->host)) {
            $process = new Process("openssl s_client -connect ".$domain.":443 -servername ".$domain);
            $process2 = new Process("echo | openssl s_client -connect ".$domain.":443 -servername ".$domain." 2>/dev/null | openssl x509 -noout -dates");
        } elseif($this->isValidIP($request->host)) {
            $process = new Process("openssl s_client -connect ".$domain.":443 -servername ".$domain);
            $process2 = new Process("echo | openssl s_client -connect ".$domain.":443 -servername ".$domain." 2>/dev/null | openssl x509 -noout -dates");
        }
        try {
            $process->mustRun();
            $process2->mustRun();
            $certificate = $process->getOutput();
            $dates = str_replace("notBefore=", "Not valid before: ", $process2->getOutput());
            $dates = str_replace("notAfter=", "Not valid after:  ", $dates);
            $isvalid = strpos($certificate, "Verification: OK");
        } catch (ProcessFailedException $e) {
            echo $e->getMessage();
        }
        echo "<br/>";
        if($isvalid) {
            echo "<h3><span class=\"badge badge-success\">SSL is valid for $domain</span></h3>";
        } else {
            echo "<h3><span class=\"badge badge-danger\">SSL is not valid for $domain</span></h3>";
        }
        echo "<pre>";
        echo "\n\n".$dates."\n";
        echo $certificate;
        echo "</pre>";
    }

    function ping(Request $request) { 
        if($this->isValidHost($request->host)) {
            $process = new Process(array('/bin/ping', '-c', '4', '-W', '1', $request->host));
            $process->start();
            echo "<pre>\n\n";
            while ($process->isRunning()) {
                echo $process->getIncrementalOutput();
                $process->clearOutput();
            }
            echo "</pre>";
        } elseif($this->isValidIP($request->host)) {
            $process = new Process(array('/bin/ping', '-c', '4', '-W', '1', $request->host));
            $process->start();
            echo "<pre>\n\n";
            while ($process->isRunning()) {
                echo $process->getIncrementalOutput();
                $process->clearOutput();
            }
            echo "</pre>";
        } else {
            echo "<br/><b>$request->host</b> couldn't be resolved.<br/><br/>";
        }
    }

    function updates(Request $request) {
        $parsedown = new ParseDown();
        return($parsedown->text(file_get_contents('../UPDATES.md')));
    }

    function isValidHost($host) {
        if(gethostbyname($host) == $host) {
            return 0;
        } else {
            return gethostbyname($host);
        }
    }

    function isValidIP($host) {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return 1;
        } else {
            return 0;
        }
    }

    function welcome(Request $request) {
        return view('welcome', [
            'cookie' => $request->cookie('albino-dnsape'),
            'clientIP' => $request->headers->get('x-forwarded-for')
        ]);
    }

    function darkMode(Request $request) {
        if($request->enabled == true) {
            return response('hi')->cookie('albino-dnsape', true, 43830);
        } elseif($request->enabled == false) {
            return response('hi')->cookie('albino-dnsape', false, 43830);
        }
    }

    function privacy(Request $request) {
        return view('privacy');
    }
}

