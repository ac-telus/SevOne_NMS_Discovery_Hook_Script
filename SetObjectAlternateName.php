<?php
/* 
    (c) 2025 - R.E.T. Team

    Program:    SetObjectAlternateName.php
    Author:	    Ludovic Felten / Roderick Olliver / Alain Albertini
    Version:    v9.0.0 (migration candidate)

    Oct. 21, 2025	v7.0.0	[LF]	- Version supporting ICMP,SNMP Availability,System,System Host,
                                      Memory,Interface,QoS,UDP Jitter,ICMP Jitter
    Oct. 27, 2026    v9.0.0        - Migrate C2C authentication, object lookup and
                                      object-type lookup; database-backed alt-name writes.
                                      Validate schema and test on NMS v9 before deployment.


    Requirements:
    - Configure the following in NMS:
      - Object Rules:
        1. 
          Device Group or Type:     All Device Groups
          Plugin:                   IP SLA Poller
          Object Type:              All Object Types
          Match:                    .*\|.*\|.*\|.*
          Status:                   Include
        2. 
          Device Group or Type:     All Device Groups
          Plugin:                   IP SLA Poller
          Object Type:              All Object Types
          Match:                    .*
          Status:                   Exclude
        Last before default include rule
          Device Group or Type:     All Device Groups
          Plugin:                   All Plugins
          Object Type:              All Object Types
          Match:                    .*
          Status:                   Exclude
      - Object Type configuration:
        1. 
          Plugin:   SNMP Poller
          Name:     Interface
          Set:      
            Description Expression: IF-MIB::ifDescr
    - To run test, a device must already be discovered.
    - In production, the hook is triggered at the end of each discovery.


    Usage:
    - To make the file available to the NMS container, copy it to /data/custom
      Ths folder is mapped into the container under the same path /data/custom

    - To switch to the NMS container run the command/alias "nms"
    
    - To test locally, from NMS container, run:
      php -r "require 'SetObjectAlternateName.php'; \\DiscoveryHook\\SetObjectAlternateName::runTest(111);"
      where "111" as an existing device ID in NMS

      runTest defaults to DRY RUN (does not write). Pass a third argument false
      to exercise actual writes in a test environment.

    - To install the hook, from NMS container, run:
      SevOne-act discovery-hooks install --filepath /data/custom/SetObjectAlternateName.php --args "{\"objectTypeNames\":\"ICMP,SNMP Availability,System,System Host,CPU,Memory,Interface,QoS,UDP Jitter,ICMP Jitter\"}"

    - To update the hook, from NMS container, run:
      SevOne-act discovery-hooks uninstall --filename SetObjectAlternateName.php
      Then install again.
*/

namespace DiscoveryHook;
include_once( 'autoload.inc' );
require_once 'DiscoveryHookDevice.inc';
require_once 'rest/C2CClient.inc';

class SetObjectAlternateName extends \DiscoveryHook\DiscoveryHookDevice {
    private $c2cClient = null;
    private $localLink = null;
    private $masterLink = null;
    private $altNameColumn = null;
    private $dryRun = false;
    private $objectTypeCache = [];

    private static $snmpPluginId = 1;
    private static $respPathPluginId = 9;
    private static $deviceUri = "/metadata/devices?deviceIds=%d";
    private static $objectsFilterUri = "/metadata/objects";

    public function __construct() {
        // Follow the v9 SetQoSDeviceHook authentication model.
        $authenticator = new \ClientCredentialsAuthentication();
        $this->c2cClient = \C2CClient::getC2CInstance();
        $this->c2cClient->authenticate($authenticator);
    }

    public function setDeviceId($deviceId) {
        $this->deviceId = $deviceId;
    }

    public function setArgs($args) {
        $this->args = $args;
        $this->dryRun = !empty($args->dryRun);
    }

    public function discoveryHook() {
        \Log::write(LOG_DEBUG, sprintf("Running SetObjectAlternateName discovery hook for device : %d", $this->deviceId));
        $device = $this->getDevice($this->deviceId);
        if (!$device) {
            return;
        }

        $this->masterLink = \Database::connectMaster();
        if (!$this->masterLink) {
            \Log::write(LOG_ERR, "!!! Unable to connect to master database for object types.");
            return;
        }

        $objectTypesIntf = array();
        $objectTypesIntf = $this->getObjectTypesFromDB(self::$snmpPluginId, 'Interface');
        if(empty($objectTypesIntf)) {
                return;
        }

        $deviceObjectsIntf = $this->getDeviceObjects($this->deviceId, self::$snmpPluginId, $objectTypesIntf);

        if(count($deviceObjectsIntf) === 0) {
                \Log::write(LOG_INFO, sprintf("No Interface objects found for device : %d", $this->deviceId));
                return;
        }
        else {
            \Log::write(LOG_DEBUG, sprintf("Found %d Interface objects found for device : %d", count($deviceObjectsIntf), $this->deviceId));
        }

        $objectTypeNames = $this->args->objectTypeNames ?? '';
        $objectTypeIds = array();
        foreach (explode(',', $objectTypeNames) as $objectTypeName) {
            $objectTypeName = trim($objectTypeName);
            if ($objectTypeName === '') {
                continue;
            }
            \Log::write(LOG_DEBUG, sprintf("Processing object type %s", $objectTypeName));
            if ($objectTypeName == "Interface") {
                $deviceObjects = $deviceObjectsIntf;
                $pluginId = self::$snmpPluginId;
            }
            else {
                if(str_ends_with($objectTypeName, "Jitter")) {
                        $pluginId = self::$respPathPluginId;
                }
                else {
                        $pluginId = self::$snmpPluginId;
                }
                $objectTypeIds = $this->getObjectTypesFromDB($pluginId, $objectTypeName);
                if(empty($objectTypeIds)) {
                    \Log::write(LOG_DEBUG, sprintf("No ObjectTypes found for: %s", $objectTypeName));
                    continue;
                }

                $deviceObjects = $this->getDeviceObjects($this->deviceId, $pluginId, $objectTypeIds);
            }

            if(!$deviceObjects) {
                \Log::write(LOG_INFO, sprintf("No $objectTypeName objects found for device : %d", $this->deviceId));
                continue;
            }
            else {
                \Log::write(LOG_DEBUG, sprintf("Found %d $objectTypeName objects found for device : %d", count($deviceObjects), $this->deviceId));
            }

            foreach( $deviceObjects as $object ) {
                //\Log::write(LOG_INFO, sprintf("Processing Object name: '%s', description: '%s', Object Id: '%s'", $object->name, $object->description, $object->id));
                if ($objectTypeName == "Interface" && count($deviceObjectsIntf) > 0) {
                    $this->handleIfObject($this->deviceId, $object);
                }
                elseif ($objectTypeName == "QoS" && count($deviceObjectsIntf) > 0) {
                    $this->handleQosObject($this->deviceId, $object, $deviceObjectsIntf);
                }
                elseif (str_ends_with($objectTypeName, "Jitter")) {
                    $this->handleRPObject($this->deviceId, $device->name, $object, $objectTypeName);
                }
				else { // By default, assume it is a "simple" object
					$this->handleSytemObjects($this->deviceId, $object, $objectTypeName);
				}
            }
        }
    }

    private function getDevice($deviceId) {
        $result = $this->c2cClient->get(sprintf(self::$deviceUri, (int)$deviceId), true);
        if (empty($result->devices)) {
            \Log::write(LOG_ERR, sprintf("!!! No device found with ID: %d", $deviceId));
            return null;
        }
        return $result->devices[0];
    }

    private function getDeviceObjects($deviceId, $pluginId, $objectTypes) : array {
        if (empty($objectTypes)) {
            return [];
        }

        $objectsList = [];
        $seenIds = [];
        $page = 0;
        $limit = 1000;
        do {
            $filter = [
                "deviceIds" => [(int)$deviceId],
                "pluginIds" => [(int)$pluginId],
                "objectTypeIds" => array_map('intval', array_keys($objectTypes)),
                "pagination" => [
                    "limit" => $limit,
                    "peerLimit" => $limit,
                    "offset" => $page * $limit
                ]
            ];
            $result = $this->c2cClient->post(self::$objectsFilterUri, $filter, true);
            $objects = $result->objects ?? [];
            $newObjects = 0;
            foreach ($objects as $object) {
                $id = (string)($object->id ?? '');
                if ($id === '' || isset($seenIds[$id])) {
                    continue;
                }
                $seenIds[$id] = true;
                $objectsList[] = $object;
                $newObjects++;
            }
            $page++;
            if (count($objects) === $limit && $newObjects === 0) {
                \Log::write(LOG_ERR, "!!! C2C metadata pagination did not advance; stopping to avoid duplicate updates.");
                break;
            }
        } while (count($objects) === $limit);

        return $objectsList;
    }

    // Mirrors SetQoSDeviceHook v9's net.plugin_object_type lookup, with
    // hex-encoded input so the configured object-type names cannot inject SQL.
    private function getObjectTypesFromDB($pluginId, $objectTypeName) : array {
        $objectTypeName = trim($objectTypeName);
        if ($objectTypeName === '') {
            return [];
        }
        $cacheKey = $pluginId . ':' . $objectTypeName;
        if (isset($this->objectTypeCache[$cacheKey])) {
            return $this->objectTypeCache[$cacheKey];
        }

        $nameHex = bin2hex($objectTypeName);
        $query = "SELECT id, name FROM net.plugin_object_type " .
                 "WHERE name LIKE CONCAT('%', CONVERT(0x{$nameHex} USING utf8mb4), '%')";
        $result = $this->masterLink->query($query);
        if ($this->masterLink->errno() != 0 || !$result) {
            \Log::write(LOG_ERR, "!!! Unable to retrieve object types: " . $this->masterLink->error());
            return [];
        }
        $types = [];
        while ($row = $result->fetchObject()) {
            // C2C object retrieval separately filters by pluginId.
            $types[$row->id] = $row;
        }
        $this->objectTypeCache[$cacheKey] = $types;
        return $types;
    }

    private function getLocalLink() {
        if (!$this->localLink) {
            $this->localLink = \Database::connectLocal();
        }
        return $this->localLink;
    }

    // Version 9's supplied QoS hook uses local database writes for indicator
    // updates. Here we use local.device_object ONLY after confirming an
    // alternate-name column actually exists. No guessed column is written.
    private function getAlternateNameColumn() {
        if ($this->altNameColumn !== null) {
            return $this->altNameColumn;
        }
        $link = $this->getLocalLink();
        if (!$link) {
            \Log::write(LOG_ERR, "!!! Unable to connect to local database.");
            return null;
        }
        $result = $link->query("SHOW COLUMNS FROM local.device_object");
        if ($link->errno() != 0 || !$result) {
            \Log::write(LOG_ERR, "!!! Cannot inspect local.device_object: " . $link->error());
            return null;
        }
        $columnNames = [];
        while ($row = $result->fetchObject()) {
            $columnNames[$row->Field] = true;
        }
        foreach (['alt_name', 'alternate_name', 'altName', 'alternateName'] as $candidate) {
            if (isset($columnNames[$candidate])) {
                $this->altNameColumn = $candidate;
                return $candidate;
            }
        }
        \Log::write(LOG_ERR, "!!! Alternate-name column not found in local.device_object; no updates will be made. Check v9 schema/REST API v3.");
        return null;
    }

    private function updateObjectAlternateName($deviceId, $objectId, $oldObjectAlternateName, $newObjectAlternateName) {
        $deviceId = (int)$deviceId;
        $objectId = (int)$objectId;
        $newObjectAlternateName = (string)$newObjectAlternateName;
        if ($deviceId <= 0 || $objectId <= 0) {
            \Log::write(LOG_ERR, "!!! Invalid device/object ID for alternate name update.");
            return false;
        }

        // Preserve v7 behavior: do nothing when old and calculated names match,
        // including when both are empty. Only substitute a space if an update
        // is actually needed and the calculated new name is empty.
        if ((string)$oldObjectAlternateName === $newObjectAlternateName) {
            return true;
        }
        if ($newObjectAlternateName === '') {
            $newObjectAlternateName = ' ';
        }
        if ($this->dryRun) {
            \Log::write(LOG_INFO, sprintf("[DRY RUN] Device %d object %d: '%s' -> '%s'",
                $deviceId, $objectId, (string)$oldObjectAlternateName, $newObjectAlternateName));
            return true;
        }

        $column = $this->getAlternateNameColumn();
        if ($column === null) {
            return false;
        }
        $link = $this->getLocalLink();
        // Escape via hex literal, and scope to a single object and device.
        $newHex = bin2hex($newObjectAlternateName);
        $query = "UPDATE local.device_object " .
                 "SET `{$column}` = CONVERT(0x{$newHex} USING utf8mb4) " .
                 "WHERE id = {$objectId} AND device_id = {$deviceId} LIMIT 1";
        $result = $link->query($query);
        if ($link->errno() != 0 || $result === false) {
            \Log::write(LOG_ERR, "!!! Unable to update object alternate name: " . $link->error());
            return false;
        }

        // Verify that the object exists on this local peer and the write stuck.
        $verify = $link->query("SELECT `{$column}` AS current_name FROM local.device_object " .
                               "WHERE id = {$objectId} AND device_id = {$deviceId} LIMIT 1");
        if ($link->errno() != 0 || !$verify || !($row = $verify->fetchObject()) ||
            (string)$row->current_name !== $newObjectAlternateName) {
            \Log::write(LOG_ERR, sprintf("!!! Alternate-name verification failed for device %d object %d.",
                $deviceId, $objectId));
            return false;
        }
        return true;
    }

    private function processIfName($ifDescription, $ifName, $objType) {
        $rules = [
            [ "matchRegex" => "Extreme .* - 1000BaseTX Port mgmt.*",             "ifReplacement" => "GigabitEthernet$1",         "qosReplacement" => "GE$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "Extreme .* - 10GbNone Port ([0-9/.]+)",           "ifReplacement" => "TenGigabitEthernet$1",      "qosReplacement" => "10GE$1",     "matchData" => $ifDescription ],
            [ "matchRegex" => "Extreme .* - Gbic1000BaseT Port ([0-9/.]+).*",    "ifReplacement" => "GigabitEthernet$1",         "qosReplacement" => "GE$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "Extreme .* - GbicLx Port ([0-9/.]+).*",           "ifReplacement" => "GigabitEthernet$1",         "qosReplacement" => "GE$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "Extreme .* - GbicNone Port ([0-9/.]+).*",         "ifReplacement" => "GigabitEthernet$1",         "qosReplacement" => "GE$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "Extreme .* - GbicSx Port ([0-9/.]+)",             "ifReplacement" => "GigabitEthernet$1",         "qosReplacement" => "GE$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "Extreme.*7400-48Y-8C - 1000Base.* Port ([0-9/.]+)", "ifReplacement" => "GigabitEthernet$1",       "qosReplacement" => "GE$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "Extreme.*7400-48Y-8C - 100Gb.* Port ([0-9/.]+)",  "ifReplacement" => "HundredGigabitEthernet$1",  "qosReplacement" => "100GE$1",    "matchData" => $ifDescription ],
            [ "matchRegex" => "Extreme.*7400-48Y-8C - 10Gb.* Port ([0-9/.]+)",   "ifReplacement" => "TenGigabitEthernet$1",      "qosReplacement" => "10GE$1",     "matchData" => $ifDescription ],
            [ "matchRegex" => "Extreme.*7400-48Y-8C - 25Gb.* Port ([0-9/.]+)",   "ifReplacement" => "TwentyFiveGigabitEthernet$1", "qosReplacement" => "25GE$1",   "matchData" => $ifDescription ],
            [ "matchRegex" => "Extreme.*7400-48Y-8C - Gbic.* Port ([0-9/.]+)",   "ifReplacement" => "GigabitEthernet$1",         "qosReplacement" => "GE$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "Extreme.*Unit ([0-9]+) Port ([0-9.]+).*",         "ifReplacement" => "Unit $1 Port $2",           "qosReplacement" => "U$1P$2",     "matchData" => $ifDescription ],
            [ "matchRegex" => "Extreme.*Port ([0-9]+)/([0-9.]+).*",              "ifReplacement" => "Unit $1 Port $2",           "qosReplacement" => "U$1P$2",     "matchData" => $ifDescription ],
            [ "matchRegex" => "Extreme.*Port ([0-9.]+).*",                       "ifReplacement" => "Port $1",                   "qosReplacement" => "P$1",        "matchData" => $ifDescription ],
            [ "matchRegex" => "Extreme.*Trunk ([0-9.]+)",                        "ifReplacement" => "Trunk $1",                  "qosReplacement" => "TK$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "Extreme.*VLAN ([0-9.]+).*",                       "ifReplacement" => "Vlan $1",                   "qosReplacement" => "VL$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "Avaya Inc., .* Media Gateway, 10/100Base-Tx, FastEthernet ([0-9/.]+)",  "ifReplacement" => "Port $1", "qosReplacement" => "TK$1",   "matchData" => $ifDescription ],
            [ "matchRegex" => "Avaya.*Out-of-band.*",                            "ifReplacement" => "",                        "qosReplacement" => "",             "matchData" => $ifDescription ],
            [ "matchRegex" => "Avaya.*Trunk ([0-9.]+)",                          "ifReplacement" => "Trunk $1",                  "qosReplacement" => "TK$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "Avaya.*Unit ([0-9]+) Port ([0-9.]+).*",           "ifReplacement" => "Unit $1 Port $2",           "qosReplacement" => "U$1P$2",     "matchData" => $ifDescription ],
            [ "matchRegex" => "Avaya.*Port ([0-9]+)/([0-9.]+).*",                "ifReplacement" => "Unit $1 Port $2",           "qosReplacement" => "U$1P$2",     "matchData" => $ifDescription ],
            [ "matchRegex" => "Avaya.*Port ([0-9.]+).*",                         "ifReplacement" => "Port $1",                   "qosReplacement" => "P$1",        "matchData" => $ifDescription ],
            [ "matchRegex" => "Avaya.*VLAN ([0-9.]+).*",                         "ifReplacement" => "Vlan $1",                   "qosReplacement" => "VL$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "10/100BaseTX Port ([0-9]+)/([0-9.]+).*",          "ifReplacement" => "Unit $1 Port $2",           "qosReplacement" => "U$1P$2",     "matchData" => $ifDescription ],
            [ "matchRegex" => "1000BaseTX Port ([0-9]+)/([0-9.]+).*",            "ifReplacement" => "Unit $1 Port $2",           "qosReplacement" => "U$1P$2",     "matchData" => $ifDescription ],
            [ "matchRegex" => "1000Gbic Port ([0-9]+)/([0-9.]+).*",              "ifReplacement" => "Unit $1 Port $2",           "qosReplacement" => "U$1P$2",     "matchData" => $ifDescription ],
            [ "matchRegex" => "1000Gbic1310Lx Port ([0-9]+)/([0-9.]+).*",        "ifReplacement" => "Unit $1 Port $2",           "qosReplacement" => "U$1P$2",     "matchData" => $ifDescription ],
            [ "matchRegex" => "1000Gbic850Sx Port ([0-9]+)/([0-9.]+).*",         "ifReplacement" => "Unit $1 Port $2",           "qosReplacement" => "U$1P$2",     "matchData" => $ifDescription ],
            [ "matchRegex" => "100BaseTX Port ([0-9]+)/([0-9.]+).*",             "ifReplacement" => "Unit $1 Port $2",           "qosReplacement" => "U$1P$2",     "matchData" => $ifDescription ],
            [ "matchRegex" => "10GbSR Port ([0-9]+)/([0-9.]+).*",                "ifReplacement" => "Unit $1 Port $2",           "qosReplacement" => "U$1P$2",     "matchData" => $ifDescription ],
            [ "matchRegex" => "Adaptive Security Appliance '(.*)' interface",    "ifReplacement" => "$1",                        "qosReplacement" => "$1",         "matchData" => $ifDescription ],
            [ "matchRegex" => "Unit: ([0-9]+) Slot: ([0-9]+) Port: ([0-9]+) Gi.*", "ifReplacement" => "GigabitEthernet$1/$2/$3", "qosReplacement" => "GE$1/$2/$3", "matchData" => $ifDescription ],
            [ "matchRegex" => "Unit: ([0-9]+) Slot: ([0-9]+) Port: ([0-9]+) TenGi.*", "ifReplacement" => "TenGigabitEthernet$1/$2/$3", "qosReplacement" => "10GE$1/$2/$3", "matchData" => $ifDescription ],
            [ "matchRegex" => "Stack Port ([0-9]+):([0-9]+)",                    "ifReplacement" => "Stack Unit $1 Port $2",     "qosReplacement" => "U$1P$2",     "matchData" => $ifDescription ],
            [ "matchRegex" => "Stack Port ([0-9]+):SP([0-9]+)",                  "ifReplacement" => "Stack Unit $1 SP $2",       "qosReplacement" => "U$1SP$2",    "matchData" => $ifDescription ],
            [ "matchRegex" => "node ([0-9]+) interface ([0-9/]+)",               "ifReplacement" => "Port $1:$2",                "qosReplacement" => "P$1:$2",     "matchData" => $ifDescription ],
            [ "matchRegex" => "Port ([0-9/.]+) - ETH.*",                         "ifReplacement" => "Port $1",                   "qosReplacement" => "U$1P$2",     "matchData" => $ifDescription ],
            [ "matchRegex" => "Port ([0-9]+)/([0-9.]+).*",                       "ifReplacement" => "Unit $1 Port $2",           "qosReplacement" => "U$1P$2",     "matchData" => $ifDescription ],
            [ "matchRegex" => "Port([0-9.:]+)",                                  "ifReplacement" => "Port $1",                   "qosReplacement" => "P$1",        "matchData" => $ifDescription ],
            [ "matchRegex" => "Port-channel([0-9.]+)",                           "ifReplacement" => "Port-channel$1",            "qosReplacement" => "PC$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "/Common/([ET]P).*(RD[0-9]).*",                    "ifReplacement" => "Trunk-$2-$1",               "qosReplacement" => "TK$2$1",     "matchData" => $ifDescription ],
            [ "matchRegex" => "10GEth([0-9/.]+)",                                "ifReplacement" => "TenGigabitEthernet$1",      "qosReplacement" => "10GE$1",     "matchData" => $ifDescription ],
            [ "matchRegex" => "40GEth([0-9/.]+)",                                "ifReplacement" => "FortyGigabitEthernet$1",    "qosReplacement" => "40GE$1",     "matchData" => $ifDescription ],
            [ "matchRegex" => "ATM([0-9/.]+)",                                   "ifReplacement" => "ATM$1",                     "qosReplacement" => "ATM$1",      "matchData" => $ifDescription ],
            [ "matchRegex" => "BDI([0-9]+)",                                     "ifReplacement" => "BDI$1",                     "qosReplacement" => "BDI$1",      "matchData" => $ifDescription ],
            [ "matchRegex" => "BVI([0-9]+)",                                     "ifReplacement" => "BVI$1",                     "qosReplacement" => "BVI$1",      "matchData" => $ifDescription ],
            [ "matchRegex" => "dedicated-ha([1-2]+)",                            "ifReplacement" => "GigabitEthernet$1",         "qosReplacement" => "GE$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "ETH ([0-9.]+)",                                   "ifReplacement" => "Ethernet$1",                "qosReplacement" => "ETH$1",      "matchData" => $ifDescription ],
            [ "matchRegex" => "ETH Port ([0-9.]+)",                              "ifReplacement" => "Ethernet$1",                "qosReplacement" => "ETH$1",      "matchData" => $ifDescription ],
            [ "matchRegex" => "eth([0-9/.]+)",                                   "ifReplacement" => "Ethernet$1",                "qosReplacement" => "ETH$1",      "matchData" => $ifDescription ],
            [ "matchRegex" => "ethernet([0-9/.]+)",                              "ifReplacement" => "Ethernet$1",                "qosReplacement" => "ETH$1",      "matchData" => $ifDescription ],
            [ "matchRegex" => "FastEthernet([0-9/.]+)",                          "ifReplacement" => "FastEthernet$1",            "qosReplacement" => "ETH$1",      "matchData" => $ifDescription ],
            [ "matchRegex" => "FastEthernet([0-9/.]+)-802.1Q vLAN subif",        "ifReplacement" => "FastEthernet$1",            "qosReplacement" => "ETH$1",      "matchData" => $ifDescription ],
            [ "matchRegex" => "FortyGigabitEthernet([0-9/.]+)",                  "ifReplacement" => "FortyGigabitEthernet$1",    "qosReplacement" => "40GE$1",     "matchData" => $ifDescription ],
            [ "matchRegex" => "ge-(#[0-9]+)",                                    "ifReplacement" => "GigabitEthernet$1",         "qosReplacement" => "GE$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "ge-([0-9/.]+)",                                   "ifReplacement" => "GigabitEthernet$1",         "qosReplacement" => "GE$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "GigabitEthernet([0-9/.\-]+)",                     "ifReplacement" => "GigabitEthernet$1",         "qosReplacement" => "GE$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "GigabitEthernet([0-9/.\-]+)-802.1Q vLAN subif",   "ifReplacement" => "GigabitEthernet$1",         "qosReplacement" => "GE$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "gigaethernet([0-9/.]+)",                          "ifReplacement" => "GigabitEthernet$1",         "qosReplacement" => "GE$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "ha([1-2]+)",                                      "ifReplacement" => "GigabitEthernet$1",         "qosReplacement" => "GE$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "Intel Corporation .* Gigabit[^;]*;eth([0-9]+)",   "ifReplacement" => "GigabitEthernet$1",         "qosReplacement" => "GE$1",       "matchData" => $ifDescription.";".$ifName ],
            [ "matchRegex" => "Intel Corporation .* 10 GbE[^;]*;eth([0-9]+)",    "ifReplacement" => "TenGigabitEthernet$1",      "qosReplacement" => "10GE$1",     "matchData" => $ifDescription.";".$ifName ],
            [ "matchRegex" => "ilo(.*)",                                         "ifReplacement" => "iLO$1",                     "qosReplacement" => "ILO$1",      "matchData" => $ifDescription ],
            [ "matchRegex" => "Lag([0-9:.]+)",                                   "ifReplacement" => "Lag $1",                    "qosReplacement" => "LAG$1",      "matchData" => $ifDescription ],
            [ "matchRegex" => "Logical Port ([0-9.]+)",                          "ifReplacement" => "Logical Port$1",            "qosReplacement" => "LP$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "Loopback([0-9]+)",                                "ifReplacement" => "Loopback$1",                "qosReplacement" => "LO$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "mgmt",                                            "ifReplacement" => "GigabitEthernet",           "qosReplacement" => "GE",         "matchData" => $ifDescription ],
            [ "matchRegex" => "MNG-ETH",                                         "ifReplacement" => "Ethernet",                  "qosReplacement" => "ETH",        "matchData" => $ifDescription ],
            [ "matchRegex" => "MXIC MX98715 100/10Base.*",                       "ifReplacement" => "Ethernet$1",                "qosReplacement" => "ETH$1",      "matchData" => $ifDescription ],
            [ "matchRegex" => "s([0-9]+)c([0-9.]+)",                             "ifReplacement" => "FortyGigabitEthernet$1/$2", "qosReplacement" => "40GE$1/$2",  "matchData" => $ifDescription ],
            [ "matchRegex" => "s([0-9]+)p([0-9.]+)",                             "ifReplacement" => "TenGigabitEthernet$1/$2",   "qosReplacement" => "10GE$1/$2",  "matchData" => $ifDescription ],
            [ "matchRegex" => "StatSession-TCP",                                 "ifReplacement" => "StatSession-TCP",           "qosReplacement" => "TCP",        "matchData" => $ifDescription ],
            [ "matchRegex" => "T1 Port ([0-9/.]+)",                              "ifReplacement" => "T1 Port $1",                "qosReplacement" => "T1P$1",      "matchData" => $ifDescription ],
            [ "matchRegex" => "T1 ([0-9/.]+)",                                   "ifReplacement" => "T1 Port $1",                "qosReplacement" => "T1P$1",      "matchData" => $ifDescription ],
            [ "matchRegex" => "TenGigabitEthernet([0-9/.]+)",                    "ifReplacement" => "TenGigabitEthernet$1",      "qosReplacement" => "10GE$1",     "matchData" => $ifDescription ],
            [ "matchRegex" => "Tunnel([0-9/.]+)",                                "ifReplacement" => "Tunnel$1",                  "qosReplacement" => "TU$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "Vlan([0-9]+)",                                    "ifReplacement" => "VLAN$1",                    "qosReplacement" => "VL$1",       "matchData" => $ifDescription ],
            [ "matchRegex" => "VSS,vBroker.*([0-9/.]+)",                         "ifReplacement" => "TenGigabitEthernet$1",      "qosReplacement" => "10GE$1",     "matchData" => $ifDescription ],
            [ "matchRegex" => "voice-port ([0-9/.]+)",                           "ifReplacement" => "FXS$1",                     "qosReplacement" => "FXS$1",      "matchData" => $ifDescription ],
            [ "matchRegex" => "ForeignExchangeOffice ([0-9/.]+)",                "ifReplacement" => "FXO$1",                     "qosReplacement" => "FXO$1",      "matchData" => $ifDescription ],
            [ "matchRegex" => "Serial([0-9/.]+)",                                "ifReplacement" => "Serial$1",                  "qosReplacement" => "S$1",        "matchData" => $ifDescription ],
            [ "matchRegex" => "sl([0-9/.]+)",                                    "ifReplacement" => "Serial$1",                  "qosReplacement" => "S$1",        "matchData" => $ifDescription ],
            [ "matchRegex" => "xe-([0-9/.]+)",                                   "ifReplacement" => "TenGigabitEthernet$1",      "qosReplacement" => "10GE$1",     "matchData" => $ifDescription ],
            [ "matchRegex" => "1/([a-z.]+)",                                     "ifReplacement" => "GigabitEthernet1/$1",       "qosReplacement" => "GE1/$1",     "matchData" => $ifDescription ]
        ];
        $modifiedIfName = $ifDescription;
        foreach($rules as $rule) {
            $preg_rule = str_replace("/", "\\/", $rule["matchRegex"]);
            if (preg_match("/^".$preg_rule."$/i", $rule["matchData"])) {
                \Log::write(LOG_DEBUG, "match: ".$rule["matchData"]." matches /^".$rule["matchRegex"]."$/i, result: ".preg_replace("/^".$preg_rule."$/i", $rule[$objType], $modifiedIfName));
                $modifiedIfName = preg_replace("/^".$preg_rule."$/i", $rule[$objType], $rule["matchData"]);
                return $modifiedIfName;
            }
        }

        return "";
    }

    private function processQueueName($queue, $vnType, $objType = "") {
        // Remap DCSP classes to Cos1-5
        // GENS naming
        if (str_starts_with($vnType, "CICG-") || str_starts_with($vnType, "IRCC-") || str_starts_with($vnType, "IRCCG-") || str_starts_with($vnType, "HRDCG-") || str_starts_with($vnType, "ESDC-") || str_starts_with($vnType, "ESDCG-")) {
            $queue=str_replace("EF", "Cos5", $queue);
            $queue=str_replace("AF3", "Cos3", $queue);
            $queue=str_replace("AF2", "Cos2", $queue);
            $queue=str_replace("AF1", "Cos1", $queue);
            if ($objType=="PCM") $queue=str_replace("default", "", $queue);
            else $queue=str_replace("default", "Cos0", $queue);
        }
        // GCNET naming
        else if ( $vnType == "GC-AAFC" || $vnType == "GC-ACOA" || $vnType == "GC-ATSSC" || $vnType == "GC-BMNT51" || $vnType == "GC-CAS" || $vnType == "GC-CBSA01" || $vnType == "GC-CED" || $vnType == "GC-CER"
                || $vnType == "GC-CFAGIDV" || $vnType == "GC-CFIA" || $vnType == "GC-CFIACRA" || $vnType == "GC-CGC" || $vnType == "GC-CHARS" || $vnType == "GC-CHRC" || $vnType == "GC-CIRB" || $vnType == "GC-CIRNAC"
                || $vnType == "GC-CNSC01" || $vnType == "GC-CRA01" || $vnType == "GC-CRA10" || $vnType == "GC-CRA11" || $vnType == "GC-CSAAISS" || $vnType == "GC-CSADWAN" || $vnType == "GC-CSAGCSI"
                || $vnType == "GC-CSAISS" || $vnType == "GC-CSCA11" || $vnType == "GC-CSPSDW" || $vnType == "GC-DFO" || $vnType == "GC-ECA14" || $vnType == "GC-ECPBL" || $vnType == "GC-ESDC800"
                || $vnType == "GC-ESDCIR" || $vnType == "GC-ESDMGMT" || $vnType == "GC-ESDMLMP" || $vnType == "GC-FINTRAC" || $vnType == "GC-GCCC" || $vnType == "GC-GCSI" || $vnType == "GC-HEALTHC"
                || $vnType == "GC-IBIBSLT" || $vnType == "GC-IC01" || $vnType == "GC-INACSRA" || $vnType == "GC-INTBELL" || $vnType == "GC-INTGOV" || $vnType == "GC-INTNET" || $vnType == "GC-INTZAYO"
                || $vnType == "GC-IRB" || $vnType == "GC-JUSB18" || $vnType == "GC-LACA21" || $vnType == "GC-MSSMGMT" || $vnType == "GC-NATGSD3" || $vnType == "GC-NDCAUS" || $vnType == "GC-NDCBN"
                || $vnType == "GC-NDCMNT" || $vnType == "GC-NDCNET" || $vnType == "GC-NDDIA" || $vnType == "GC-NDDNET" || $vnType == "GC-NDDRSN" || $vnType == "GC-NDDSSN" || $vnType == "GC-NDFAA1"
                || $vnType == "GC-NDGPNET" || $vnType == "GC-NDITWAA" || $vnType == "GC-NDMCE" || $vnType == "GC-NDMST1" || $vnType == "GC-NDNIPR" || $vnType == "GC-NDRNET" || $vnType == "GC-NDRNET2"
                || $vnType == "GC-NDRNET3" || $vnType == "GC-NDSIPR" || $vnType == "GC-NDSSN" || $vnType == "GC-NDSTRAT" || $vnType == "GC-NDTNET" || $vnType == "GC-NDWADN" || $vnType == "GC-NDWCS"
                || $vnType == "GC-NDWCSCNM" || $vnType == "GC-NDWCSNM" || $vnType == "GC-NDWOS" || $vnType == "GC-NDXNET" || $vnType == "GC-NFB" || $vnType == "GC-NRCAN" || $vnType == "GC-NRCCORP"
                || $vnType == "GC-NRCMGMT" || $vnType == "GC-NRCPE1" || $vnType == "GC-NRCRSCH" || $vnType == "GC-NRCTNS" || $vnType == "GC-OCOL" || $vnType == "GC-OSFI" || $vnType == "GC-PARKSC"
                || $vnType == "GC-PCHB2" || $vnType == "GC-PCOVFSO" || $vnType == "GC-PE2RCM" || $vnType == "GC-POB26" || $vnType == "GC-PPTC" || $vnType == "GC-PSB29" || $vnType == "GC-PSCPROD"
                || $vnType == "GC-PSOFT" || $vnType == "GC-PSPBM00" || $vnType == "GC-PSPBM51" || $vnType == "GC-PSPCB30" || $vnType == "GC-PSPCBMN" || $vnType == "GC-PSPCCSP" || $vnType == "GC-PSPCINF"
                || $vnType == "GC-PSPCPCO" || $vnType == "GC-PSPCTEL" || $vnType == "GC-PWB30" || $vnType == "GC-PWDW" || $vnType == "GC-PWTP" || $vnType == "GC-RCMBRIP" || $vnType == "GC-RCMCCIS"
                || $vnType == "GC-RCMCRAL" || $vnType == "GC-RCMCRIP" || $vnType == "GC-RCMCRN" || $vnType == "GC-RCMCRRA" || $vnType == "GC-RCMERIP" || $vnType == "GC-RCMESN" || $vnType == "GC-RCMFRIP"
                || $vnType == "GC-RCMGRIP" || $vnType == "GC-RCMHRIP" || $vnType == "GC-RCMKRIP" || $vnType == "GC-RCMNPSN" || $vnType == "GC-RCMNRIP" || $vnType == "GC-RCMNSP" || $vnType == "GC-RCMORIP"
                || $vnType == "GC-RCMP3" || $vnType == "GC-RCMSURR" || $vnType == "GC-RCMTOPS" || $vnType == "GC-RCMVVIP" || $vnType == "GC-SMNET" || $vnType == "GC-SNCFIA" || $vnType == "GC-SSCBM51"
                || $vnType == "GC-SSCCS" || $vnType == "GC-SSCENTB" || $vnType == "GC-SSCGSA" || $vnType == "GC-SSCINFR" || $vnType == "GC-SSCMGT" || $vnType == "GC-STATS" || $vnType == "GC-STATSB33"
                || $vnType == "GC-TBSCACS" || $vnType == "GC-TCA32" || $vnType == "GC-TFC" || $vnType == "GC-TSBC" || $vnType == "GC-VAC" || $vnType == "GC-VOIP" || $vnType == "GC-VPN110" || $vnType == "GC-WCSCNM"
                || $vnType == "GC-WCSCNMT" || $vnType == "GC-WCSDATA" || $vnType == "GC-WCSDATT" || $vnType == "GC-WCSSA" || $vnType == "GC-WED" || $vnType == "GC-ZTCMN" || $vnType == "GC-ZTSMNET"
                || $vnType == "GC-ZZTEST" || $vnType == "GCNET-CNM" || str_starts_with($vnType, "GC-")) {
            $queue=str_replace("EF", "Cos5", $queue);
            $queue=str_replace("AF3", "Cos4", $queue);
            $queue=str_replace("AF2", "Cos3", $queue);
            $queue=str_replace("AF1", "Cos2", $queue);
            if ($objType=="PCM") $queue=str_replace("default", "", $queue);
            else $queue=str_replace("default", "Cos1", $queue);
        }
        // non GoC naming
        else {
            // keep existing values "EF", "AF1", "AF2", etc.
        }

        return $queue;
    }

    private function handleSytemObjects($deviceId, $object, $objectTypeName) {
        $name=$object->name;
        $sysDescription = $object->info->systemDescription ?? '';
        $altName = "";

        if ($objectTypeName=="System") 
            $altName="System";
        elseif ($objectTypeName=="System Host") 
            $altName="System";
        elseif ($objectTypeName=="ICMP") 
            $altName="Availability ICMP";
        elseif ($objectTypeName=="SNMP Availability") 
            $altName="Availability SNMP";
        elseif ($objectTypeName == "CPU") {
            if ($sysDescription=="CPU" || 
                str_contains($sysDescription, "cpu") || 
                str_contains($sysDescription, "Data Processor") || 
                str_contains($sysDescription, "Intel") || 
                str_contains($sysDescription, "intel") ||
                str_contains($sysDescription, "AMD")
                ) {
                if ($name=="CPU") 
                    $altName="CPU";
                elseif (preg_match("/^CPU([0-9]+)$/", $name)) 
                    $altName=preg_replace("/^CPU([0-9]+)$/", "CPU $1", $name);
            }
        }
        elseif ($objectTypeName == "Memory") {
            if ($name=="Memory" || 
                $name=="Mem" || 
                $name=="Slot-0 Management Memory"
                ) 
                $altName="Memory";
            elseif (preg_match("/^Memory([0-9]+)$/", $name) && 
                ($sysDescription=="Processor" || $sysDescription=="Memory")
                ) 
                $altName=preg_replace("/^Memory([0-9]+)$/", "Memory $1", $name);
            elseif (preg_match("/system heap/i", $name)) 
                $altName="Memory";
            elseif (preg_match("/^(Virtual|Physical|Real) memory$/i", $name)) 
                $altName=preg_replace("/^(Virtual|Physical|Real) memory$/i", "Memory $1", $name);
            elseif ($name=="Swap space" || 
                $name=="Swap" || 	
                $name=="Slot-0 Management Swap")  
                $altName="Memory Swap";
            elseif ($name=="Supervisor Memory") 
                $altName="Memory Supervisor";
        }
		else return(false);

        if (!$this->updateObjectAlternateName($deviceId, $object->id, ($object->altName ?? $object->alternateName ?? ''), $altName)) {
            return false;
        }
        \Log::write(LOG_INFO, ($this->dryRun ? "[DRY RUN] Would set" : "Set") . " alternate name for System/CPU/Memory object '$object->name' to '$altName'");

        return( true );
    }

    private function handleIfObject($deviceId, $object) {

        if (!isset($object->info->systemDescription)) {
            \Log::write(LOG_ERR, "!!! Interface object '" . $object->name . "' has no systemDescription in C2C response; skipping rename.");
            return false;
        }
        $modifiedIfName = $this->processIfName($object->info->systemDescription, $object->name, "ifReplacement");

        if (!$this->updateObjectAlternateName($deviceId, $object->id, ($object->altName ?? $object->alternateName ?? ''), $modifiedIfName)) {
            return false;
        }
        \Log::write(LOG_INFO, ($this->dryRun ? "[DRY RUN] Would set" : "Set") . " alternate name for Interface object '$object->name' to '$modifiedIfName'");

        return( true );
    }

    private function handleQosObject($deviceId, $object, $deviceObjectsIntf ) {
        $parts = explode(" - ", $object->name);
        $ifParts = explode(' ', $parts[0]);
        $ifName = $ifParts[0];
        $qosDirection = strtoupper($ifParts[1]);
        $svPolicyName = preg_replace('/-([1-2]?[0-9]?[0-9].){3}[1-2]?[0-9]?[0-9]$/', '', $parts[count($parts)-2]);
        $suffix = explode(' ', $parts[count($parts)-1]);
        $svCMName = preg_replace('/-([1-2]?[0-9]?[0-9].){3}[1-2]?[0-9]?[0-9]$/', '', $suffix[0]);
        $svObjType = $suffix[1];

		$ifDescription = '';
        foreach( $deviceObjectsIntf as $intf) {
            if ($intf->name == $ifName) {
                $ifDescription = $intf->info->systemDescription ?? '';
                //\Log::write(LOG_DEBUG, "found ifdescr = '".$intf->description."'");
                break;
            }
        }

        if ($ifDescription === '') {
            \Log::write(LOG_ERR, "!!! QoS object '" . $object->name . "' has no matched Interface systemDescription; skipping rename.");
            return false;
        }

        // $objType is a custom variable to identify ClassMap = CM or Parent Class = PCM
        if ($svObjType == "Class") {
            $objType="CM";
            if ($svPolicyName && $svCMName) {
                if (str_contains($svPolicyName, "PARENT_") || str_contains($svCMName, "PCM_")) {
                    $objType="PCM";
                }
            }
        }
        elseif ($svObjType == "Police") {
            $objType="PL";
        }
        else return true;

        //use "(?i)" in replaceAll for case insensitive
        $modifiedIfName = $this->processIfName($ifDescription, $ifName, "qosReplacement");

        // $netType is a custom variable indicating if QoS is applied to LAN or WAN data
        $netType="UnknownPolicy";
        if ($svPolicyName) {
            if (str_contains($svPolicyName, "LAN_")) {
                $netType="LAN";
            } else if (str_contains($svPolicyName, "WAN_")) {
                $netType="WAN";
            } else if (str_contains($svPolicyName, "ICP_")) {
                $netType="ICP";
            } else {
                $netType="UnknownNetType";
            }
        }

        // Not used for now
        $orgCode="";

        // $vnType is a custom variable containing the customer's VN Name
        $vnType="";
        if ($svPolicyName) {
            $vnType=$svPolicyName;
            $vnType=str_replace("IN_", "", $vnType);
            $vnType=str_replace("OUT_", "", $vnType);
            $vnType=str_replace("WAN_", "", $vnType);
            $vnType=str_replace("LAN_", "", $vnType);
            $vnType=str_replace("ICP_", "", $vnType);
            $vnType=str_replace("PARENT_", "", $vnType);
            $vnType=preg_replace("/MEA$/", "", $vnType);
            $vnType=preg_replace("/PER_VPN$/", "", $vnType);
        }

        // Remove the noise the the classmap name to keep only the class of service (AFx, EF, etc.)
        $modifiedQosClassMapName="UnknownClassMap";
        if ($svCMName) {
            $modifiedQosClassMapName=$svCMName;
            $modifiedQosClassMapName=str_replace("IN_", "", $modifiedQosClassMapName);
            $modifiedQosClassMapName=str_replace("OUT_", "", $modifiedQosClassMapName);
            $modifiedQosClassMapName=str_replace("WAN_", "", $modifiedQosClassMapName);
            $modifiedQosClassMapName=str_replace("LAN_", "", $modifiedQosClassMapName);
            $modifiedQosClassMapName=str_replace("ICP_", "", $modifiedQosClassMapName);
            $modifiedQosClassMapName=str_replace("PCM_", "", $modifiedQosClassMapName);
            $modifiedQosClassMapName=str_replace("class-default", "default", $modifiedQosClassMapName);
            $modifiedQosClassMapName=str_replace("QOS_GROUPS", "", $modifiedQosClassMapName);
            $modifiedQosClassMapName=str_replace("QOS_GROUP", "", $modifiedQosClassMapName);
            $modifiedQosClassMapName=str_replace("CONTROL", "CTRL", $modifiedQosClassMapName);
            $modifiedQosClassMapName=str_replace("MANAGEMENT", "MGMT", $modifiedQosClassMapName);
            $modifiedQosClassMapName=str_replace("ROUTING", "RTNG", $modifiedQosClassMapName);
            $modifiedQosClassMapName=str_replace("_TRAFFIC", "", $modifiedQosClassMapName);
            $modifiedQosClassMapName=str_replace("_PROTOCOL", "", $modifiedQosClassMapName);
        }

        $modifiedQosClassMapName = $this->processQueueName($modifiedQosClassMapName, $vnType, $objType);

        // Build the final item name
        $fullQoSName="QOS-".$modifiedIfName."-".$qosDirection."-".$objType."-".$netType."_".$vnType."_".$modifiedQosClassMapName;
        $fullQoSName=str_replace("__", "_", $fullQoSName);
        $fullQoSName=preg_replace("/_$/", "", $fullQoSName);

        if (!$this->updateObjectAlternateName($deviceId, $object->id, ($object->altName ?? $object->alternateName ?? ''), $fullQoSName)) {
            return false;
        }
        \Log::write(LOG_INFO, ($this->dryRun ? "[DRY RUN] Would set" : "Set") . " alternate name for QoS object '$object->name' to '$fullQoSName'");

        return( true );

    }


    private function handleRPObject($deviceId, $deviceName, $object, $objectTypeName ) {
        // jitter-136!20!20!5000!!4.4.90.98!45013!150!!9!6!1127!CAABLTBR-RTR014990|PRI|ALSLAB01-VRFFAG|AF3|PRO--Index:1127-ToS:136
        $type_map = array (
            'UDP Jitter' => 'JIT',
            'ICMP Jitter' => 'ICM'
        );

        if (!isset($object->ipsla->owner)) {
            \Log::write(LOG_ERR, "!!! Response Path object '" . $object->name . "' has no IPSLA owner in C2C response; skipping rename.");
            return false;
        }
        $ownerInfo = $object->ipsla->owner;

        if (array_key_exists($objectTypeName, $type_map)) {
            $rpTypeSuffix = $type_map[$objectTypeName];
            $rpTypeLabel = $objectTypeName;
        }
        else {
            $rpTypeSuffix = "UnknownRespPathType";
            $rpTypeLabel = "Unknown Type";
        }

        // Set default
        $rpName = "";

        // Using owner string if set.
        if ($ownerInfo && preg_match("/.*[|].*[|].*[|].*/", $ownerInfo)) {
            $destinationDev = preg_replace("/^([^|]*)[|]([^|]*)[|]([^|]*)[|]([^|]*).*/", "$1", $ownerInfo);
            $pathType = preg_replace("/^([^|]*)[|]([^|]*)[|]([^|]*)[|]([^|]*).*/", "$2", $ownerInfo);
            $vnType = preg_replace("/^([^|]*)[|]([^|]*)[|]([^|]*)[|]([^|]*).*/", "$3", $ownerInfo);
            $queueClass = preg_replace("/^([^|]*)[|]([^|]*)[|]([^|]*)[|]([^|]*).*/", "$4", $ownerInfo);
            // Remove Sonar attributes from beginning of string, if present
            $destinationDev = preg_replace("/.*!/", "", $destinationDev);

            $queueClass = $this->processQueueName($queueClass, $vnType);

            // for GONET, shorten concentrator end to a "site name"
            if (str_starts_with("GO", $vnType) || str_starts_with("INET-", $vnType)) {
                $deviceName=preg_replace("/-.*/", "", $deviceName);
            }

            $rpName = $destinationDev."-".$pathType."-".$vnType."-".$queueClass."-".$deviceName."-".$rpTypeSuffix;
        }

        if (!$this->updateObjectAlternateName($deviceId, $object->id, ($object->altName ?? $object->alternateName ?? ''), $rpName)) {
            return false;
        }
        \Log::write(LOG_INFO, ($this->dryRun ? "[DRY RUN] Would set" : "Set") . " alternate name for Response Path object '$object->name' to '$rpName'");

        return( true );

    }

    public static function runTest($deviceId, $objectTypeNames = "ICMP,SNMP Availability,System,System Host,CPU,Memory,Interface,QoS,UDP Jitter,ICMP Jitter", $dryRun = true) {
        \Log::setLevel( LOG_DEBUG );
        \Log::setStyle(\Log::STYLE_STDOUT);
        $alt = new SetObjectAlternateName();
        $alt->setDeviceId($deviceId);
        $alt->setArgs((object)array("objectTypeNames" => $objectTypeNames, "dryRun" => $dryRun));
        $alt->discoveryHook();
    }
};

?>