-- 07_register.lua — transport registrations (UDP, USB, BLE, DLT_USER0).
-- Part of the trezor_dissector Wireshark plugin. Edit here, then run ../build.sh


-- UDP emulator, packet size 64. The port(s) come from the configurable
-- preference (default 21324). We register the whole configured range, and
-- re-register whenever the user changes the preference. We also keep the UDP
-- heuristic as a fallback so traffic on an unconfigured port can still match.
local udp_table = DissectorTable.get("udp.port")
local registered_udp_ports = {}

-- Parse "21324" or "21324-21400" or "21324,21326" into a list of port numbers.
local function parse_ports(spec)
    local ports = {}
    if spec == nil then return ports end
    for part in tostring(spec):gmatch("[^,]+") do
        part = part:gsub("%s", "")
        local lo, hi = part:match("^(%d+)%-(%d+)$")
        if lo ~= nil then
            for p = tonumber(lo), tonumber(hi) do ports[#ports + 1] = p end
        else
            local single = part:match("^(%d+)$")
            if single ~= nil then ports[#ports + 1] = tonumber(single) end
        end
    end
    return ports
end

local function register_udp_ports()
    -- Unregister previously added ports.
    for _, p in ipairs(registered_udp_ports) do
        udp_table:remove(p, thp)
    end
    registered_udp_ports = parse_ports(thp.prefs.udp_ports)
    for _, p in ipairs(registered_udp_ports) do
        udp_table:add(p, thp)
    end
end

register_udp_ports()
thp:register_heuristic("udp", thp.dissector)

-- Re-register when the user changes the port preference.
function thp.prefs_changed()
    register_udp_ports()
end

-- DLT_USER0 (link-layer type 147): synthetic pcaps that carry raw Trezor
-- frames from byte 0 with no transport wrapper (e.g. produced by
-- capture_codec_v1.py via trezorlib chunk hooks). Packet size 64 (USB/HID).
-- Registering here lets "trezor_dissector" decode User 0 frames. Depending on
-- the Wireshark version you may still need to map it once under
-- Edit > Preferences > Protocols > DLT_USER (User 0 -> trezor_dissector).
pcall(function()
    local wtap_table = DissectorTable.get("wtap_encap")
    local user0 = nil
    if wtap ~= nil and wtap.USER0 ~= nil then
        user0 = wtap.USER0
    end
    if user0 ~= nil then
        wtap_table:add(user0, thp)
    end
end)

-- USB: HID interrupt and WebUSB/vendor bulk, packet size 64.
local USB_PACKET_SIZE = 64
thp:register_heuristic("usb.interrupt", function(buffer, pinfo, tree)
    thp_packet_size = USB_PACKET_SIZE
    local consumed = thp.dissector(buffer, pinfo, tree)
    return consumed and consumed > 0
end)
thp:register_heuristic("usb.bulk", function(buffer, pinfo, tree)
    thp_packet_size = USB_PACKET_SIZE
    local consumed = thp.dissector(buffer, pinfo, tree)
    return consumed and consumed > 0
end)

-- Optional direct bind to Trezor VID:PID (1209:53c1) via usb.product.
-- Works only when Wireshark obtained the device descriptor; in VM USB
-- passthrough it is often missing, in which case the heuristics above apply.
pcall(function()
    DissectorTable.get("usb.product"):add(0x120953c1, function(buffer, pinfo, tree)
        thp_packet_size = USB_PACKET_SIZE
        return thp.dissector(buffer, pinfo, tree)
    end)
end)

-- BLE: Trezor Safe 7, packet size 244. THP travels as a GATT characteristic
-- value, dissected on the Bluetooth ATT layer.
-- NOTE: assumes THP control byte starts at offset 0 of the ATT value.
-- If a real Safe 7 BLE capture shows a leading offset, slice the buffer here.
pcall(function()
    thp:register_heuristic("btatt", function(buffer, pinfo, tree)
        thp_packet_size = 244
        local consumed = thp.dissector(buffer, pinfo, tree)
        return consumed and consumed > 0
    end)
end)