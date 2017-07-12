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

    private function Login() {
        $this->baseURL = $this->ReadPropertyString("IPAddress");
        $this->userName = $this->ReadPropertyString("UserName");
        $this->userPassword = $this->ReadPropertyString("UserPassword");

        # init curl object and set session-wide options
        $this->ch = curl_init();


        curl_setopt($this->ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($this->ch, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($this->ch, CURLOPT_SSL_VERIFYHOST, FALSE);
        curl_setopt($this->ch, CURLOPT_COOKIEFILE, "/tmp/unifi_cookie");
        curl_setopt($this->ch, CURLOPT_COOKIEJAR, "/tmp/unifi_cookie");
        curl_setopt($this->ch, CURLOPT_SSLVERSION, 1); //set TLSv1 (SSLv3 is no longer supported)
        # authenticate against unifi controller
        $url = $this->baseURL . "/api/login";
        $json = "{'username':'" . $this->userName . "', 'password':'" . $this->userPassword . "'}";

        curl_setopt($this->ch, CURLOPT_URL, $url);
        curl_setopt($this->ch, CURLOPT_POST, 1);
        curl_setopt($this->ch, CURLOPT_POSTFIELDS, $json);

        curl_exec($this->ch);
    }

    private function Logout() {
        $url = $this->baseURL . "/api/logout";
        curl_setopt($this->ch, CURLOPT_URL, $url);
        curl_setopt($this->ch, CURLOPT_POST, 0);
        curl_setopt($this->ch, CURLOPT_POSTFIELDS, NULL);
        curl_setopt($this->ch, CURLOPT_HTTPGET, TRUE);
        curl_exec($this->ch);

        curl_close($this->ch);
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
            $VarID = IPS_GetObjectIDByIdent($Ident, $ParentID);
            if (false !== $VarID) {
                SetVariable($VarID, $Type, $Value);
                return;
            }
        }
        $VarID = IPS_GetObjectIDByName($Name, $ParentID);
        if (false !== $VarID) { // exists?
            $Obj = IPS_GetObject($VarID);
            if (2 == $Obj['ObjectType']) { // is variable?
                $Var = IPS_GetVariable($VarID);
                if ($Type == $Var['VariableValue']['ValueType']) {
                    SetVariable($VarID, $Type, $Value);
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
        SetVariable($VarID, $Type, $Value);
    }
    
    private function GetWLANnetworks($instance_WLAN_ID) {
        $wlanList = $this->GetWLANConfig();

        foreach ($wlanList->data as $wlan) {
            $ident = $wlan->_id;
            $catID = CreateCategoryByNameIdent($wlan->name, $ident, $instance_WLAN_ID);
            #CreateVariable("ID", 3, $wlan->_id, $ident . "_id", $catID);
            #CreateVariable("Enabled", 0, $wlan->enabled, $ident . "_enabled", $catID);
#
            #$enabledID = IPS_GetVariableIDByName("Enabled", $catID);
           # IPS_SetVariableCustomAction($enabledID, $setWLANID);
            #IPS_SetVariableCustomProfile($enabledID, "~Switch");

            #CreateVariable("Security", 3, $wlan->security, $ident . "_security", $catID);
        }
    }

    public function ApplyChanges() {
        //Never delete this line!
        parent::ApplyChanges();

        $this->baseURL = $this->ReadPropertyString("IPAddress");
        $this->userName = $this->ReadPropertyString("UserName");
        $this->userPassword = $this->ReadPropertyString("UserPassword");
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
