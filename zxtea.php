<?php
class XTEA {
    private $key;
    private $cbc = true;

    function __construct($key) {
        $this->key_setup($key);
    }

    public function check_implementation() {
        $xtea = new XTEA('');
        $vectors = array(array(array(0x00000000,0x00000000,0x00000000,0x00000000),array(0x41414141,0x41414141),array(0xed23375a,0x821a8c2d)),array(array(0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f),array(0x41424344,0x45464748),array(0x497df3d0,0x72612cb5)));
        $retval = true;

        foreach ($vectors as $vector) {
            $key = $vector[0];
            $plain = $vector[1];
            $cipher = $vector[2];
            $xtea->key_setup($key);
            $return = $xtea->block_encrypt($vector[1][0],$vector[1][1]);

            if ((int)$return[0] != (int)$cipher[0] ||
                (int)$return[1] != (int)$cipher[1]) {
                $retval = false;
            }
        }

        return $retval;
    }

    // fungsi encrypt ditukar dengan fungsi decrypt
    public function encrypt($text) {
        $plain = array();
        $cipher = $this->_str2long(base64_decode($text));

        if ($this->cbc == 1) {
            $i = 2;
        } else {
            $i = 0;
        }

        for ($i; $i < count($cipher); $i += 2) {
            $return = $this->block_decrypt($cipher[$i],$cipher[$i+1]);
            if ($this->cbc == 1) {
                $plain[] = array($return[0]^$cipher[$i-2],$return[1]^$cipher[$i-1]);
            } else {
                $plain[] = $return;
            }
        }

        $output = '';

        for ($i = 0; $i < count($plain); $i++) {
            $output .= $this->_long2str($plain[$i][0]);
            $output .= $this->_long2str($plain[$i][1]);
        }

        return rtrim($output);
    }

    // fungsi decrypt ditukar dengan fungsi encrypt
    public function decrypt($text) {
        $n = strlen($text);

        if ($n%8 != 0) {
            $lng = ($n+(8-($n%8)));
        } else {
            $lng = 0;
        }

        $text = str_pad($text,$lng,'');
        $text = $this->_str2long($text);

        if ($this->cbc) {
            $cipher[0][0] = time();
            $cipher[0][1] = (double)microtime() * 1000000;
        }

        $a = 1;

        for ($i = 0; $i < count($text); $i +=2) {
            if ($this->cbc) {
                $text[$i] ^= $cipher[$a-1][0];
                $text[$i+1] ^= $cipher[$a-1][1];
            }

            $cipher[] = $this->block_encrypt($text[$i],$text[$i+1]);
            $a++;
        }

        $output = '';

        for ($i = 0; $i < count($cipher); $i++) {
            $output .= $this->_long2str($cipher[$i][0]);
            $output .= $this->_long2str($cipher[$i][1]);
        }

        return base64_encode($output);
    }

    private function block_decrypt($y,$z) {
        $delta = 0x9e3779b9;
        $sum = 0xC6EF3720;
        $n = 32;

        for ($i = 0; $i < 32; $i++) {
            $z = $this->_add($z,-($this->_add($y<<4^$this->_rshift($y,5),$y)^$this->_add($sum,$this->key[$this->_rshift($sum,11)&3])));
            $sum = $this->_add($sum,-$delta);
            $y = $this->_add($y,-($this->_add($z<<4^$this->_rshift($z,5),$z)^$this->_add($sum,$this->key[$sum&3])));
        }

        return array($y,$z);
    }

    private function block_encrypt($y,$z) {
        $sum = 0;
        $delta = 0x9e3779b9;

        for ($i = 0; $i < 32; $i++) {
            $y = $this->_add($y,$this->_add($z<<4^$this->_rshift($z,5),$z)^$this->_add($sum,$this->key[$sum&3]));
            $sum = $this->_add($sum,$delta);
            $z = $this->_add($z,$this->_add($y<<4^$this->_rshift($y,5),$y)^$this->_add($sum,$this->key[$this->_rshift($sum,11)&3]));
        }

        $v[0] = $y;
        $v[1] = $z;
        return array($y,$z);
    }

    private function key_setup($key) {
        if (is_array($key)) {
            $this->key = $key;
        } elseif (isset($key) && !empty($key)) {
            $this->key = $this->_str2long(str_pad($key,16,$key));
        } else {
            $this->key = array(0,0,0,0);
        }
    }

    private function _add($i1,$i2) {
        $result = 0.0;

        foreach (func_get_args() as $value) {
            if (0.0 > $value) {
                $value -= 1.0+0xffffffff;
            }

            $result += $value;
        }

        if (0xffffffff < $result || -0xffffffff > $result) {
            $result = fmod($result,0xffffffff+1);
        }

        if (0x7fffffff < $result) {
            $result -= 0xffffffff + 1.0;
        } elseif (-0x80000000 > $result) {
            $result += 0xffffffff + 1.0;
        }

        return$result;
    }


    private function _rshift($integer,$n) {
        if (0xffffffff < $integer || -0xffffffff > $integer) {
            $integer = fmod($integer,0xffffffff+1);
        }

        if (0x7fffffff < $integer) {
            $integer -= 0xffffffff + 1.0;
        } elseif (-0x80000000 > $integer) {
            $integer += 0xffffffff + 1.0;
        }

        if (0 > $integer) {
            $integer &= 0x7fffffff;
            $integer >>= $n;
            $integer |= 1 << (31-$n);
        } else {
            $integer >>= $n;
        }

        return $integer;
    }

    private function _str2long($data) {
        $n = strlen($data);
        $tmp = unpack('N*',$data);
        $data_long = array();
        $j = 0;

        foreach ($tmp as $value) {
            $data_long[$j++] = $value;
        }

        return $data_long;
    }

    private function _long2str($l) {
        return pack('N',$l);
    }
}

function get_enc_key($param_1) {
    $v_1 = '';
    $v_5 = ceil(strlen($param_1)/3)*3;
    $v_6 = str_pad($param_1,$v_5,'0',STR_PAD_LEFT);

    for ($i = 0; $i < (strlen($v_6)/3); $i++) {
        $v_1 .= chr(substr(strval($v_6),$i*3,3));
    }
    return $v_1;
}

if (!empty($argv[1])) {
    $co = array("ssl"=>array("verify_peer"=>false,"verify_peer_name"=>false));
    $di = file_get_contents($argv[1], false, stream_context_create($co));

    if (preg_match_all("/'([^']+)'/", $di, $r, PREG_PATTERN_ORDER)) {
        $x_tea = new XTEA(get_enc_key(str_replace("'", "", $r[0][3])));
        $x_res = trim($x_tea->encrypt(str_replace("'", "", $r[0][4])));

        preg_match('/"([^"]+)"\)\)\)/', $x_res, $a);
        echo str_replace(';', ";\n", gzinflate(base64_decode(str_replace(['"',')'], '', $a[0]))));
    }
} else {
    echo "Usage: zxtea.php <file>\n";
}
?>