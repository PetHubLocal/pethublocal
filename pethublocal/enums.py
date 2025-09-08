"""
    Pet Hub Constants

    Constants used by Pet Hub Local
    Used and abused surepy constants from Ben's amazing work: https://github.com/benleb/surepy

    Copyright (c) 2022, Peter Lambrechtsen (peter@crypt.nz)
"""
from enum import IntEnum, IntFlag

class SureEnum(IntEnum):
    """ Sure Int enum for integer based enums """
    def __str__(self) -> str:
        return self.name.title()

    def as_hex(self):
        """ as hex """
        bytestring = self.to_bytes(4, 'little').hex()
        return " ".join(bytestring[i:i + 2] for i in range(0, len(bytestring), 2))

    @classmethod
    def has_value(cls, value):
        """ has value """
        return value in cls._value2member_map_

    @classmethod
    def has_member(cls, value):
        """ has member """
        return value.upper() in cls._member_names_

    @classmethod  # Handle weird values, as it really shouldn't crash
    def _missing_(cls, value):
        """ missing """
        new_member = int.__new__(cls, value)
        new_member._name_ = str(value)
        new_member._value_ = value
        return cls._value2member_map_.setdefault(value, new_member)



class SureFlag(IntFlag):
    """ Sure Flag enum for flag based enums which are Custom Modes to bitwise operators. """
    def string_array(self):
        """ string_array """
        return [member for member in self._member_names_ if member in str(self)]

    @classmethod
    def has_value(cls, value):
        """ has_value """
        return value in cls._value2member_map_

    @classmethod
    def has_member(cls, value):
        """ has_member """
        return value in cls._member_names_


class EntityType(SureEnum):
    """ Sure Entity Types. """
    Pet           = 0   # artificial ID, not used by the Sure Petcare API
    Hub           = 1   # Hub
    Repeater      = 2   # Repeater
    PetDoor       = 3   # Pet Door Connect
    Feeder        = 4   # Microchip Pet Feeder Connect
    Programmer    = 5   # Programmer
    CatFlap       = 6   # Cat Flap Connect
    FeederLite    = 7   # Feeder Lite
    Poseidon      = 8   # Poseidon <s>Felaqua</s> Connect
    Devices       = 13  # artificial ID, Pet Flap + Cat Flap + Feeder = 3 + 6 + 4 = 13  ¯\_(ツ)_/¯


class DeviceRegister(SureEnum):
    """ Device Registers """
    TIME          = 0x07   # Device Time registers
    CONFIG        = 0x09   # Config registers
    UNKNOWN0B     = 0x0b   # Unknown 0b message
    BATTERY       = 0x0c   # Battery state change
    BOOT10        = 0x10   # Boot message 10
    TAGS          = 0x11   # Tag provisioning
    CUSTOM        = 0x14   # Custom Modes
    STATUS16      = 0x16   # Status 16 message, happens each time feeder manually opened
    BOOT17        = 0x17   # Boot message 17
    FEEDER        = 0x18   # Feeder state change
    POSEIDON      = 0x1b   # Feeder state change


# def DeviceGetData(dataval):
#     """ Feeder states """
#     getdatatype = Box({
#         'Time'      : '07 00',     # Time
#         'Config'    : '09 00 ff',  # Config registers
#         'Unknown0b' : '0b 00',     # Unknown 0b
#         'Battery'   : '0c 00',     # Battery state
#         'Boot10'    : '10 00',     # Boot message 10
#         'Tags'      : '11 00 ff',  # Tag provisioned
#         'Boot17'    : '17 00 00',  # Boot message  17
#     })
#     if dataval in getdatatype:
#         return bytearray.fromhex(getdatatype[dataval])
#     else:
#         return bytearray()
#

class FeederState(SureEnum):
    """ Feeder states """
    ANIMAL_OPEN     = 0          # Animal Open Feeder
    ANIMAL_CLOSED   = 1          # Animal Closed Feeder
    INTRUDER_CLOSED = 2          # Intruder Mode Active and second animal turned up so closed feeder
    MANUAL_OPEN     = 4          # Manually Opened Feeder
    MANUAL_CLOSED   = 5          # Manually Closed Feeder
    ZERO_BOTH       = 6          # Zero Feeder both scales
    ZERO_BOWL1      = 7          # Zero Feeder left scale
    ZERO_BOWL2      = 8          # Zero Feeder right scale


class FeederZeroScales(SureEnum):
    """ Feeder Zero Scales """
    ZEROBOWL1    = 1               # Zero Feeder left scale
    ZEROBOWL2    = 2               # Zero Feeder right scale
    ZEROBOTH     = 3               # Zero Feeder both scales


class FeederCloseDelay(SureEnum):
    """ Feeder Close Delay Speed """
    FAST         = 0               # Fast delay   - 0 Seconds
    NORMAL       = 4000            # Normal delay - 4 Seconds
    POSEIDON     = 5000            # Poseidon
    SLOW         = 20000           # Slow delay   - 20 Seconds


class FeederBowls(SureEnum):
    """ Feeder Bowl Count """
    ONE           = 1         # Single Bowl
    TWO           = 2         # Double Bowl
    POSEIDON      = 4         # Poseidon


class PetDoorLockState(SureEnum):
    """ PetDoorLockState """
    UNLOCKED        = 0
    KEEPIN          = 1
    KEEPOUT         = 2
    LOCKED          = 3
    CURFEW          = 4
    CURFEW_LOCKED   = -1
    CURFEW_UNLOCKED = -2
    CURFEW_UNKNOWN  = -3


class LockState(SureEnum):
    """ Lock State IDs. """
    UNLOCKED        = 0
    KEEPIN          = 1
    KEEPOUT         = 2
    LOCKED          = 3
    CURFEW          = 4


class PetDoorLockedOutState(SureEnum):
    """ PetDoorLockedOutState Locked Out State for preventing animals coming in """
    NORMAL          = 2                 # Allow pets in
    LOCKEDOUT       = 3                 # Keep pets out


class CatFlapLockState(SureEnum):
    """ Cat Flap Lock State from message type 11. """
    NORMAL          = 2  # This is when a cat is provisioned in normal in / out mode
    KEEPIN          = 3  # This applies to the cat when they are individually being kept in, and if the device is 07, then it is applying to the door
    LOCKED          = 4  # Locked
    KEEPOUT         = 5  # Keep Out
    UNLOCKED        = 6  # Unlocked


class PetDoorDirection(SureEnum):
    """  Pet Movement on Pet Door coming in or out or looked in or unknown animal left """
    Outside_LookedIn    = 0x40     # This happens if the pet comes up to the door from outside, puts head in and unlocks the door but doesn't come in.
    Inside              = 0x61     # Normal ingress
    Outside             = 0x62     # Normal egress
    Inside_Already      = 0x81     # Ingress if the pet door thought the pet was already inside
    Outside_Already     = 0x82     # Door thinks pet was already outside
    Outside_UnknownTag  = 0xd3     # This along with pet 621 is when the pet leaves too quickly for the pet door to read it leaving


class CurfewState(SureEnum):
    """ Curfew State """
    DISABLED        = 0
    OFF             = 1
    ON              = 2
    STATUS          = 3


class CatFlapCurfewState(SureEnum):
    """ CatFlapCurfew State """
    OFF             = 6
    ON              = 3


class HubLeds(SureEnum):
    """ Hub LED State register offset 0x18 """
    OFF             = 0      # Ears Off
    BRIGHT          = 1      # Bright Ears
    DIMMED          = 4      # Dimmed
    FLASHOFF        = 0x80   # Flash Leds 3 times when off
    FLASHBRIGHT     = 0x81   # Flash Leds 3 times when bright
    FLASHDIMMED     = 0x84   # Flash Leds 3 times when dimmed


class HubAdoption(SureEnum):
    """ Hub adoption / pairing_mode mode register offset 0x15 """
    DISALBED        = 0      # Not attempting to pair a new device
    ENABLED         = 2      # In pairing / adoption mode
    BUTTON          = 0x82   # Pairing mode enabled by pressing 'reset' button underneath


class ProvChipFrom(SureEnum):
    """ ProvChipFrom  Chip Provisioned From """
    EXISTING        = 0        # Already provisioned on device
    BUTTON          = 1        # Provisioned chip from learn button on the back
    NEWCLOUD        = 2        # Provisioned chip from cloud
    DISABLED        = 3        # Provisioned chip from cloud


class TagState(SureEnum):
    """ Tag State on Non Pet-Door Device """
    ENABLED         = 0
    DISABLED        = 1
    LOCKSTATE       = 2


class CatFlapDirection(SureEnum):
    """ Pet Movement on Cat Flap coming in or going out. """
    Outside         = 0x0000  # Animal went out
    Inside          = 0x0101  # Animal came in
    LOOKEDIN        = 0x0201  # Animal Looked in, door unlocked, but didn't come in
    LOOKEDOUT       = 0x0200  # Animal Looked out, door unlocked, but didn't go out
    STATUS2         = 0x0202  # Status 2, this happens a lot with above messages
    STATUS1         = 0x0102  # Random Status message I don't know if this happens but added for completeness


class Animal(SureEnum):
    """ Animal mdi mapping """
    alien        = 0
    cat          = 1
    dog          = 2
    cow          = 3
    robot        = 4


class AnimalState(SureEnum):
    """ Animal State """
    Outside          = 0
    Inside           = 1
    Unknown          = 2


# class DeviceState(SureEnum):
#     """ Device online or offline """
#     Offline          = 0
#     Online           = 1


class Enabled(SureEnum):
    """  Enabled disabled """
    DISABLED         = 0
    ENABLED          = 1


class OnOff(SureEnum):
    """  On/OFF """
    OFF              = 0
    ON               = 1
    STATUS           = 2

class FeederCustomMode(SureFlag):
    """ Custom Modes on the Feeder """
    Disabled = 0         # All custom modes disabled
    BIT1 = 0x1           # Bit1 - ?
    BIT2 = 0x2           # Bit2 - ?
    BIT3 = 0x4           # Bit3 - ?
    BIT4 = 0x8           # Bit4 - ?
    BIT5 = 0x10          # Bit5 - ?
    BIT6 = 0x20          # Bit6 - ?
    NonSelective = 0x40  # Bit7 - Non-selective Entry - Allow any animal who breaks the infrared link to open feeder
    GeniusCat = 0x80     # Bit8 - Genius Cat Mode - Disable open/close button as Genius Cat has figured out how to open the feeder by pressing button.
    Intruder = 0x100     # Bit9 - Intruder Mode - Close lid when another non-provisioned tag turns up
    BIT10 = 0x200        # Bit10 - ?
    BIT11 = 0x400        # Bit11 - ?
    BIT12 = 0x800        # Bit12 - ?
    BIT13 = 0x1000       # Bit13 - ?
    BIT14 = 0x2000       # Bit14 - ?
    BIT15 = 0x4000       # Bit15 - ?
    BIT16 = 0x8000       # Bit16 - ?

    """
        Other Modes:
        German Funk Antenna
        Extended Mode
        Proximity Test
    """


class PetDoorCustomMode(SureFlag):
    """ Custom Modes on the Pet Door """
    NonSelective = 0x1        # Custom Mode 1 - Non-selective Entry - Unlocks the door inbound so any animal can come in
    Rechargeables = 0x2       # Custom Mode 2 - Rechargeable Batteries so work with lower voltage from 1.2v Rechargeables vs 1.5v Alkaline
    ThreeSeconds = 0x4        # Custom Mode 3 - Timid Pets - 3 Seconds delay before closing door
    TenSeconds = 0x8          # Custom Mode 4 - Slower Locking - 10 Seconds delay before closing door
    Intruder = 0x10           # Custom Mode 5 - Intruder Mode - Lock outside locks when non-provisioned animal detected by sensor to prevent door being pulled open
    OppositeCurfew = 0x20     # Custom Mode 6 - Opposite Curfew mode - Lock KeepOut rather than KeepIn
    LockedCurfew = 0x40       # Custom Mode 7 - Fully Locking Curfew Mode - Locks both in and out locks when in curfew mode
    MetalMode1 = 0x80         # Custom Mode 8 - Metal Interference - This mode will help with severe metal interference in an installation
    MetalMode2 = 0x100        # Custom Mode 9 - Metal Interference - This mode will help with severe metal interference in an installation
    ExtendedRange = 0x200     # Custom Mode 10 - Extended Mode - Extend frequency of scanning the tags
    ExtendedIntruder = 0x400  # Custom Mode 11 - Extended Intruder Mode - Extended Intruder Mode - Registers presence of intruder animal trying to enter the house and closes outside lock to prevent door being pulled open for longer period
    BIT12 = 0x800             # Bit12 - ?
    DoubleChip1 = 0x1000      # Custom Mode 13 - Double Chip Operating Mode 1 - Allow animal with two tags interfering with each other to enter
    DoubleChip2 = 0x2000      # Custom Mode 14 - Double Chip Operating Mode 2 - Allow animal with two tags interfering with each other to enter
    DoubleChip3 = 0x4000      # Custom Mode 15 - Double Chip Operating Mode 3 - Allow animal with two tags interfering with each other to enter
    ProximityTest = 0x8000    # Custom Mode 16 - Proximity Sensor Test - Test the proximity function of the door.


    """
    class CatFlapCustomMode(SureFlag):  # Custom Modes on the Feeder
        Disabled = 0           # All custom modes disabled

    Remove Battery, Press and hold the Add Pet Button, Add Battery, Light will be Solid Red
        Double Chip Operating Mode - Flashing Green
        Erase All Custom Modes - Alternating Red and Green
        Extended Mode - Solid Red
        Failsafe Mode - Flashing Orange
        Fast Locking Mode - Flashing Red
        Non-selective Exit Mode - Solid Green
        Metal Mode - Solid Orange
    To activate the mode press and hold Add Pet Button for 3 seconds.

    class PoseidonCustomMode(SureFlag):  # Custom Modes on the Poseidon (Felaqua)

        Disabled = 0           # All custom modes disabled

     Range Test Kit Mode -   Put Felaqua into Learn Mode using App. Pets -> Add -> Felaqua -> Green Led flashing on Felaqua
                             Press Connect button on Felaqua, Light flashing Red.
                             Move Tag near feeder and will Start to flash green when tag is detected
                             Press Connect button to exit Range Test Kit mode.
    """

class PoseidonState(SureEnum):
    """ Poseidon / Felaqua State from message type 1b """
    DRINK          = 0  # Water level went down from drinking, no animal detected
    ANIMALDRINK    = 1  # Water level went down from drinking, animal detected
    REMOVED        = 2  # When the bottle is removed, and the scales go to the top
    REFILLED       = 3  # Water Refilled
