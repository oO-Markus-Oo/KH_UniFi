<?
define('__ROOT__', dirname(dirname(__FILE__)));
require_once (__ROOT__ . '/libs/class.unifi.php');

class UniFi extends IPSModule {
    /**
     * public properties
     */
    public $ch = '';
    public $user = '';
    public $password = '';
    public $site = 'default';
    public $baseurl = 'https://127.0.0.1:8443';
    public $version = '5.4.16';

    /**
     * private properties
     */
    private $debug = false;
    private $is_loggedin = false;
    private $cookies = '';
    private $request_type = 'POST';
    private $last_results_raw;
    private $last_error_message;

    public function Create() {
        //Never delete this line!
        parent::Create();

        //These lines are parsed on Symcon Startup or Instance creation
        //You cannot use variables here. Just static values.
        $this->RegisterPropertyString("IPAddress", "https://127.0.0.1:8443");
        $this->RegisterPropertyString("UserName", "admin");
        $this->RegisterPropertyString("UserPassword", "");
        $this->RegisterPropertyString("Clients", "");
        $this->RegisterPropertyString("Site", "");
        $this->RegisterPropertyInteger("Intervall_Network", 0);
        $this->RegisterPropertyInteger("Intervall_Client", 0);
        $this->RegisterPropertyBoolean("Debug", FALSE);
        $this->RegisterTimer("Intervall_Network", 0, 'UniFi_UpdateUniFiNetworkData($_IPS[\'TARGET\']);');
        $this->RegisterTimer("Intervall_Client", 0, 'UniFi_UpdateUniFiClientData($_IPS[\'TARGET\']);');
    }

    private function CreateCategoryByIdent($id, $ident, $name) {
        $cid = @IPS_GetObjectIDByIdent($this->maskUmlaute($ident), $id);
        if ($cid === false) {
            $cid = IPS_CreateCategory();
            IPS_SetParent($cid, $id);
            IPS_SetName($cid, $name);
            IPS_SetIdent($cid, $this->maskUmlaute($ident));
        } else {
            IPS_SetName($cid, $name);
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
        $VarID = @IPS_GetObjectIDByName($Name, $ParentID);
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

    private function GetWLANclients($instance_Clients_ID, $instance_Clients_Presence_ID) {
        $clientList = $this->list_clients();

        if (is_object($this->last_results_raw)) {
            foreach ($this->last_results_raw->data as $client) {
                if ($client->is_wired === FALSE) {
                    if (!isset($client->hostname) AND isset($client->name)) {
                        $client->hostname = $client->name;
                    }
                    if (!isset($client->name) AND isset($client->hostname)) {
                        $client->name = $client->hostname;
                    }
                    if (!isset($client->name) AND ! isset($client->hostname)) {
                        $client->name = $client->mac;
                        $client->hostname = $client->mac;
                    }
                    $ident = str_replace(":", "", $client->mac);
                    $ident = str_replace("-", "", $ident);
                    $this->ClientArrayOnline[] = $ident;
                    $catID = $this->CreateCategoryByIdent($instance_Clients_ID, $ident . "_name", $client->name);
                    $this->CreateVariable("MAC", 3, $client->mac, $ident . "_mac", $catID);
                    $this->CreateVariable("IP", 3, $client->ip, $ident . "_ip", $catID);
                    $this->CreateVariable("Hostname", 3, $client->hostname, $ident . "_hostname", $catID);
                    $this->CreateVariable("Signal", 1, $client->signal, $ident . "_signal", $catID);
                    $this->CreateVariable("Radio", 3, $client->radio, $ident . "_radio", $catID);
                    $this->CreateVariable("TX Bytes", 1, $client->tx_bytes, $ident . "_txbytes", $catID);
                    $this->CreateVariable("RX Bytes", 1, $client->rx_bytes, $ident . "_rxbytes", $catID);
                    $this->CreateVariable("Uptime", 1, $client->uptime, $ident . "_uptime", $catID);
                }
            }
        }

        foreach ($this->ClientArray as $obj) {
            $varClientMAC = str_replace(":", "", $obj->varDeviceMAC);
            $varClientMAC = str_replace("-", "", $varClientMAC);

            if (in_array($varClientMAC, $this->ClientArrayOnline, TRUE)) {
                $varOnlineID = $this->CreateVariable($obj->varDeviceName, 0, TRUE, $varClientMAC . "_presence", $instance_Clients_Presence_ID);
            } else
                $varOnlineID = $this->CreateVariable($obj->varDeviceName, 0, FALSE, $varClientMAC . "_presence", $instance_Clients_Presence_ID);
        }
    }

    private function GetLANclients($instance_Clients_ID, $instance_Clients_Presence_ID) {
        $clientList = $this->list_clients();

        if (is_object($this->last_results_raw)) {
            foreach ($this->last_results_raw->data as $client) {
                if ($client->is_wired === TRUE) {
                    if (!isset($client->hostname) AND isset($client->name)) {
                        $client->hostname = $client->name;
                    }
                    if (!isset($client->name) AND isset($client->hostname)) {
                        $client->name = $client->hostname;
                    }
                    if (!isset($client->name) AND ! isset($client->hostname)) {
                        $client->name = $client->mac;
                        $client->hostname = $client->mac;
                    }
                    $ident = str_replace(":", "", $client->mac);
                    $ident = str_replace("-", "", $ident);
                    $this->ClientArrayOnline[] = $ident;
                    $catID = $this->CreateCategoryByIdent($instance_Clients_ID, $ident . "_name", $client->name);
                    $this->CreateVariable("MAC", 3, $client->mac, $ident . "_mac", $catID);
                    $this->CreateVariable("IP", 3, $client->ip, $ident . "_ip", $catID);
                    $this->CreateVariable("Hostname", 3, $client->hostname, $ident . "_hostname", $catID);
                    $this->CreateVariable("Uptime", 1, $client->uptime, $ident . "_uptime", $catID);
                }
            }
        }

        foreach ($this->ClientArray as $obj) {
            $varClientMAC = str_replace(":", "", $obj->varDeviceMAC);
            $varClientMAC = str_replace("-", "", $varClientMAC);

            if (in_array($varClientMAC, $this->ClientArrayOnline, TRUE)) {
                $varOnlineID = $this->CreateVariable($obj->varDeviceName, 0, TRUE, $varClientMAC . "_presence", $instance_Clients_Presence_ID);
            } else
                $varOnlineID = $this->CreateVariable($obj->varDeviceName, 0, FALSE, $varClientMAC . "_presence", $instance_Clients_Presence_ID);
        }
    }

    private function GetWLANnetworks($instance_WLAN_ID) {
        $wlanList = $this->list_wlanconf();

        if (is_object($this->last_results_raw)) {
            foreach ($this->last_results_raw->data as $wlan) {
                $ident = $wlan->_id;
                $catID = $this->CreateCategoryByIdent($instance_WLAN_ID, $ident, $wlan->name);
                $this->CreateVariable("ID", 3, $wlan->_id, $ident . "_id", $catID);
                $this->CreateVariable("Enabled", 0, $wlan->enabled, $ident . "_enabled", $catID);
                $this->CreateVariable("Security", 3, $wlan->security, $ident . "_security", $catID);
            }
        }
    }

    public function ApplyChanges() {
        //Never delete this line!
        parent::ApplyChanges();

        $this->baseURL = $this->ReadPropertyString("IPAddress");
        $this->user = $this->ReadPropertyString("UserName");
        $this->password = $this->ReadPropertyString("UserPassword");
        $this->site = $this->ReadPropertyString("Site");
        $this->version = '5.4.16';
        $this->checkIntervalNetwork = $this->ReadPropertyInteger("Intervall_Network");
        $this->checkIntervalClient = $this->ReadPropertyInteger("Intervall_Client");
        $this->debug = $this->ReadPropertyBoolean("Debug");

        $this->SetTimerInterval("Intervall_Network", ($this->ReadPropertyInteger("Intervall_Network") * 1000));
        $this->SetTimerInterval("Intervall_Client", ($this->ReadPropertyInteger("Intervall_Client") * 1000));

        # create neccessary folders
        $instance_id_parent = $this->InstanceID;
        $instance_Clients_ID = $this->CreateCategoryByIdent($instance_id_parent, "Clients", "Clients");
        $instance_WLAN_ID = $this->CreateCategoryByIdent($instance_id_parent, "WLAN", "WLAN");

        $this->UpdateUniFiNetworkData();
        $this->UpdateUniFiClientData();
    }

    public function UpdateUniFiNetworkData() {
        $this->baseURL = $this->ReadPropertyString("IPAddress");
        $this->user = $this->ReadPropertyString("UserName");
        $this->password = $this->ReadPropertyString("UserPassword");
        $this->site = $this->ReadPropertyString("Site");
        $this->version = '5.4.16';
        $this->checkIntervalNetwork = $this->ReadPropertyInteger("Intervall_Network");
        $this->checkIntervalClient = $this->ReadPropertyInteger("Intervall_Client");
        $this->debug = $this->ReadPropertyBoolean("Debug");
        $this->Login();

        # create neccessary folders
        $instance_id_parent = $this->InstanceID;
        $instance_WLAN_ID = $this->CreateCategoryByIdent($instance_id_parent, "WLAN", "WLAN");

        $this->GetWLANnetworks($instance_WLAN_ID);
        $this->Logout();
    }

    public function UpdateUniFiClientData() {
        $this->baseURL = $this->ReadPropertyString("IPAddress");
        $this->user = $this->ReadPropertyString("UserName");
        $this->password = $this->ReadPropertyString("UserPassword");
        $this->site = $this->ReadPropertyString("Site");
        $this->version = '5.4.16';
        $this->checkIntervalNetwork = $this->ReadPropertyInteger("Intervall_Network");
        $this->checkIntervalClient = $this->ReadPropertyInteger("Intervall_Client");
        $this->debug = $this->ReadPropertyBoolean("Debug");
        $this->ClientArray = json_decode($this->ReadPropertyString("Clients"));
        $this->Login();

        # create neccessary folders
        $instance_id_parent = $this->InstanceID;
        $instance_Clients_ID = $this->CreateCategoryByIdent($instance_id_parent, "Clients", "Clients");
        $instance_Clients_Wireless_ID = $this->CreateCategoryByIdent($instance_Clients_ID, "Wireless", "Wireless");
        $instance_Clients_LAN_ID = $this->CreateCategoryByIdent($instance_Clients_ID, "LAN", "LAN");
        $instance_Clients_Presence_ID = $this->CreateCategoryByIdent($instance_Clients_ID, "Presence", "_Presence");

        $this->GetWLANclients($instance_Clients_Wireless_ID, $instance_Clients_Presence_ID);
        $this->GetLANclients($instance_Clients_LAN_ID, $instance_Clients_Presence_ID);
        $this->Logout();
    }

}
?>