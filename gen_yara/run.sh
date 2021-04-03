#!/bin/bash
# Declare associative array mapping the algorithm to their magic numbers
declare -A rules
rules["aes"]="0x630x7c0x770x7b0xf20x6b0x6f0xc50x300x010x670x2b0xfe0xd70xab0x760xca0x820xc90x7d0xfa0x590x470xf00xad0xd40xa20xaf0x9c0xa40x720xc00xb70xfd0x930x260x360x3f0xf70xcc0x340xa50xe50xf10x710xd80x310x150x040xc70x230xc30x180x960x050x9a0x070x120x800xe20xeb0x270xb20x750x090x830x2c0x1a0x1b0x6e0x5a0xa00x520x3b0xd60xb30x290xe30x2f0x840x530xd10x000xed0x200xfc0xb10x5b0x6a0xcb0xbe0x390x4a0x4c0x580xcf0xd00xef0xaa0xfb0x430x4d0x330x850x450xf90x020x7f0x500x3c0x9f0xa80x510xa30x400x8f0x920x9d0x380xf50xbc0xb60xda0x210x100xff0xf30xd20xcd0x0c0x130xec0x5f0x970x440x170xc40xa70x7e0x3d0x640x5d0x190x730x600x810x4f0xdc0x220x2a0x900x880x460xee0xb80x140xde0x5e0x0b0xdb0xe00x320x3a0x0a0x490x060x240x5c0xc20xd30xac0x620x910x950xe40x790xe70xc80x370x6d0x8d0xd50x4e0xa90x6c0x560xf40xea0x650x7a0xae0x080xba0x780x250x2e0x1c0xa60xb40xc60xe80xdd0x740x1f0x4b0xbd0x8b0x8a0x700x3e0xb50x660x480x030xf60x0e0x610x350x570xb90x860xc10x1d0x9e0xe10xf80x980x110x690xd90x8e0x940x9b0x1e0x870xe90xce0x550x280xdf0x8c0xa10x890x0d0xbf0xe60x420x680x410x990x2d0x0f0xb00x540xbb0x16"
rules["blake"]="0x6A09E6670xBB67AE850x3C6EF3720xA54FF53A0x510E527F0x9B05688C0x1F83D9AB0x5BE0CD19"
rules["keccak"]="0x00000000000000010x00000000000080820x800000000000808a0x80000000800080000x000000000000808b0x00000000800000010x80000000800080810x80000000000080090x000000000000008a0x00000000000000880x00000000800080090x000000008000000a0x000000008000808b0x800000000000008b0x80000000000080890x80000000000080030x80000000000080020x80000000000000800x000000000000800a0x800000008000000a0x80000000800080810x80000000000080800x00000000800000010x8000000080008008"
rules["groestl"]=${rules[aes]}
rules["jh"]="0xeb0x980xa30x410x2c0x200xd30xeb0x920xcd0xbe0x7b0x9c0xb20x450xc10x1c0x930x510x910x600xd40xc70xfa0x260x000x820xd60x7e0x500x8a0x030xa40x230x9e0x260x770x260xb90x450xe00xfb0x1a0x480xd40x1a0x940x770xcd0xb50xab0x260x020x6b0x170x7a0x560xf00x240x420x0f0xff0x2f0xa80x710xa30x960x890x7f0x2e0x4d0x750x1d0x140x490x080xf70x7d0xe20x620x270x760x950xf70x760x240x8f0x940x870xd50xb60x570x470x800x290x6c0x5c0x5e0x270x2d0xac0x8e0x0d0x6c0x510x840x500xc60x570x050x7a0x0f0x7b0xe40xd30x670x700x240x120xea0x890xe30xab0x130xd30x1c0xd70x69"
rules["skein"]="0xCCD044A12FDB3E130xE83590301A79A9EB0x55AEA0614F816E6F0x2A2767A4AE9B94DB0xEC06025E74DD76830xE7A436CDC47462510xC36FBAF9393AD1850x3EEDBA1833EDFC13"

# Generate yara rules
for key in ${!rules[@]};
do
    echo "Generating ${key} - ${rules[$key]}";
    python3 gen_yara.py $key ${rules[$key]};
    echo "";
done

# Move output *rule files into rules folder
if [ ! -d "rules" ] 
then
    mkdir rules
fi

mv *.rule rules

# Run python script to convert all rules into a single js string for ingesting into yara-wasm
python3 convert_rules.py