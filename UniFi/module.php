<?
class UniFi extends IPSModule {

    var $ch;
    var $baseURL;
    var $userName;
    var $userPassword;

    public function Create() {
        //Never delete this line!
        parent::Create();

        //These lines are parsed on Symcon Startup or Instance creation
        //You cannot use variables here. Just static values.
        $this->RegisterPropertyString("IPAddress", "https://127.0.0.1:8443");
        $this->RegisterPropertyString("UserName", "admin");
        $this->RegisterPropertyString("UserPassword", "");
        $this->RegisterPropertyString("Clients", "");
        $this->RegisterPropertyInteger("Intervall", 0);
    }

    /**
     * Login to UniFi Controller
     */
    public function login()
    {
        $ch = $this->get_curl_obj();

        curl_setopt($ch, CURLOPT_HEADER, 1);
        curl_setopt($ch, CURLOPT_REFERER, $this->baseurl.'/login');
        curl_setopt($ch, CURLOPT_URL, $this->baseurl.'/api/login');
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(['username' => $this->user, 'password' => $this->password]));

        if (($content = curl_exec($ch)) === false) {
            error_log('cURL error: '.curl_error($ch));
        }

        if ($this->debug) {
            curl_setopt($ch, CURLOPT_VERBOSE, true);

            print '<pre>';
            print PHP_EOL.'-----------LOGIN-------------'.PHP_EOL;
            print_r (curl_getinfo($ch));
            print PHP_EOL.'----------RESPONSE-----------'.PHP_EOL;
            print $content;
            print PHP_EOL.'-----------------------------'.PHP_EOL;
            print '</pre>';
        }

        $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $body        = trim(substr($content, $header_size));
        $code        = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        curl_close ($ch);

        preg_match_all('|Set-Cookie: (.*);|U', substr($content, 0, $header_size), $results);
        if (isset($results[1])) {
            $this->cookies = implode(';', $results[1]);
            if (!empty($body)) {
                if (($code >= 200) && ($code < 400)) {
                    if (strpos($this->cookies, 'unifises') !== false) {
                        $this->is_loggedin = true;
                    }
                }

                if ($code === 400) {
                     error_log('We have received an HTTP response status: 400. Probably a controller login failure');
                     return $code;
                }
            }
        }

        return $this->is_loggedin;
    }

    /**
     * Logout from UniFi Controller
     */
    public function logout()
    {
        if (!$this->is_loggedin) return false;
        $this->exec_curl($this->baseurl.'/logout');
        $this->is_loggedin = false;
        $this->cookies     = '';
        return true;
    }

    private function GetClients() {
        $this->Login();

        $url = $this->baseURL . "/api/s/default/stat/sta";

        curl_setopt($this->ch, CURLOPT_URL, $url);
        curl_setopt($this->ch, CURLOPT_POST, 1);
        curl_setopt($this->ch, CURLOPT_POSTFIELDS, "json={}");
        $response = curl_exec($this->ch);

        $this->Logout();

        if ($response !== false) {
            return json_decode($response);
        } else {
            return 0;
        }
    }

    private function GetWLANConfig() {
        $this->Login();

        $url = $this->baseURL . "/api/s/default/list/wlanconf";
        curl_setopt($this->ch, CURLOPT_URL, $url);
        curl_setopt($this->ch, CURLOPT_POST, 1);
        curl_setopt($this->ch, CURLOPT_POSTFIELDS, "json={}");
        $response = curl_exec($this->ch);

        $this->Logout();

        if ($response !== false) {
            return json_decode($response);
        } else {
            return 0;
        }
    }

    private function SetWLANConfig($groupID, $config) {
        $this->Login();

        $url = $this->baseURL . "/api/s/default/upd/wlanconf/" . $groupID;
        curl_setopt($this->ch, CURLOPT_URL, $url);
        curl_setopt($this->ch, CURLOPT_POST, 1);
        curl_setopt($this->ch, CURLOPT_POSTFIELDS, "json=" . json_encode($config) . "");
        curl_exec($this->ch);

        $this->Logout();
    }

    private function CreateCategoryByNameIdent($name, $Ident = '', $ParentID = 0, $pos = 0, $hidden = false) {
        global $_IPS;
        if ($Ident <> '') {
            $Catid = @IPS_GetObjectIDByIdent($Ident, $ParentID);
        }
        if (($Ident === '') OR ($Catid === false) OR ($Catid === '')) {
            $Catid = @IPS_GetCategoryIDByName($name, $ParentID);
        }

        if ($Catid === false) {
            $Catid = IPS_CreateCategory();
            IPS_SetParent($Catid, $ParentID);
            IPS_SetName($Catid, $name);
            IPS_SetPosition($Catid, $pos);
            IPS_SetHidden($Catid, $hidden);
            IPS_SetInfo($Catid, "This category was created by: #" . $_IPS['SELF'] . "#");
        }
        return $Catid;
    }

    private function maskUmlaute($text)
    {
        $text = str_replace ("ä", "a", $text);
        $text = str_replace ("Ä", "AE", $text);
        $text = str_replace ("ö", "oe", $text);
        $text = str_replace ("Ö", "OE", $text);
        $text = str_replace ("ü", "ue", $text);
        $text = str_replace ("Ü", "UE", $text);
        $text = str_replace ("ß", "ss", $text);
        $text = str_replace (" ", "_", $text);
        $text = str_replace ("(", "_", $text);
        $text = str_replace (")", "_", $text);
        $text = str_replace ("&", "_", $text);
        $text = str_replace ("§", "_", $text);
        $text = str_replace ("/", "_", $text);
        $text = str_replace ("=", "_", $text);
        $text = str_replace ("{", "_", $text);
        $text = str_replace ("}", "_", $text);
        $text = str_replace (":", "_", $text);
        $text = str_replace (",", "_", $text);
        $text = str_replace (";", "_", $text);
     
        return $text;
    }
    
    private function CreateCategoryByIdent($id, $ident, $name)
    {
        $cid = @IPS_GetObjectIDByIdent($this->maskUmlaute($ident), $id);
        if($cid === false)
        {
             $cid = IPS_CreateCategory();
             IPS_SetParent($cid, $id);
             IPS_SetName($cid, $name);
             IPS_SetIdent($cid, $this->maskUmlaute($ident));
        }
        return $cid;
    }
    
    private function SetVariable($VarID, $Type, $Value) {
        switch ($Type) {
            case 0: // boolean
                SetValueBoolean($VarID, $Value);
                break;
            case 1: // integer
                SetValueInteger($VarID, $Value);
                break;
            case 2: // float
                SetValueFloat($VarID, $Value);
                break;
            case 3: // string
                SetValueString($VarID, $Value);
                break;
        }
    }

    private function CreateVariable($Name, $Type, $Value, $Ident = '', $ParentID = 0) {
        //echo "CreateVariable: ( $Name, $Type, $Value, $Ident, $ParentID ) \n";
        if ('' != $Ident) {
            $VarID = @IPS_GetObjectIDByIdent($Ident, $ParentID);
            if (false !== $VarID) {
                $this->SetVariable($VarID, $Type, $Value);
                return;
            }
        }
        $VarID = IPS_GetObjectIDByName($Name, $ParentID);
        if (false !== $VarID) { // exists?
            $Obj = IPS_GetObject($VarID);
            if (2 == $Obj['ObjectType']) { // is variable?
                $Var = IPS_GetVariable($VarID);
                if ($Type == $Var['VariableValue']['ValueType']) {
                    $this->SetVariable($VarID, $Type, $Value);
                    return;
                }
            }
        }
        $VarID = IPS_CreateVariable($Type);
        IPS_SetParent($VarID, $ParentID);
        IPS_SetName($VarID, $Name);
        if ('' != $Ident) {
            IPS_SetIdent($VarID, $Ident);
        }
        $this->SetVariable($VarID, $Type, $Value);
    }
    
    private function GetWLANnetworks($instance_WLAN_ID) {
        $wlanList = $this->GetWLANConfig();

        foreach ($wlanList->data as $wlan) {
            $ident = $wlan->_id;
            $catID = $this->CreateCategoryByNameIdent($wlan->name, $ident, $instance_WLAN_ID);
            $this->CreateVariable("ID", 3, $wlan->_id, $ident . "_id", $catID);
            $this->CreateVariable("Enabled", 0, $wlan->enabled, $ident . "_enabled", $catID);
            $this->CreateVariable("Security", 3, $wlan->security, $ident . "_security", $catID);
        }
    }

    public function ApplyChanges() {
        //Never delete this line!
        parent::ApplyChanges();

        $this->baseurl = $this->ReadPropertyString("IPAddress");
        $this->user = $this->ReadPropertyString("UserName");
        $this->password = $this->ReadPropertyString("UserPassword");
        $this->site = "Default";
        $this->version = '5.4.16';
        $this->checkInterval = $this->ReadPropertyInteger("Intervall");

        $this->RegisterVariableString("ClientHTMLBox", "ClientHTMLBox", "~HTMLBox");
        
        # create neccessary folders
        $instance_id_parent = $this->InstanceID;
        $instance_Clients_ID = $this->CreateCategoryByIdent($instance_id_parent, "Clients", "Clients");
        $instance_WLAN_ID    = $this->CreateCategoryByIdent($instance_id_parent, "WLAN", "WLAN");

        $this->GetWLANnetworks($instance_WLAN_ID);
        #$updateClientsScript = file_get_contents(__DIR__ . "/createClientList.php");
        #$updateClientsScriptID = $this->RegisterScript("updateClients", "updateClients", $updateClientsScript);
        #IPS_SetScriptTimer($updateClientsScriptID, $this->checkInterval);

        #$updateWLANScript = file_get_contents(__DIR__ . "/createWLANList.php");
        #$updateWLANScriptID = $this->RegisterScript("updateWLAN", "updateWLAN", $updateWLANScript);
        #IPS_SetScriptTimer($updateWLANScriptID, $this->checkInterval);

        #$setWLANScript = file_get_contents(__DIR__ . "/setWLAN.php");
        #$this->RegisterScript("setWLAN", "setWLAN", $setWLANScript);
    }    
}

?>
