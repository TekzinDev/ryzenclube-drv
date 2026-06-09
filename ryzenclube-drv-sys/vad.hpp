#pragma once

// VAD tree walk + ControlArea analysis
// Detects section remapping (MEM_IMAGE → MEM_PRIVATE)

#define OFF_MMVAD_SHORT_STARTINGVPN   0x18
#define OFF_MMVAD_SHORT_ENDINGVPN     0x1c
#define OFF_MMVAD_SHORT_VPNHIGH_START 0x20
#define OFF_MMVAD_SHORT_VPNHIGH_END   0x21
#define OFF_MMVAD_SHORT_FLAGS         0x30
#define OFF_MMVAD_SUBSECTION          0x48
#define OFF_SUBSECTION_CONTROLAREA    0x0
#define OFF_CONTROLAREA_MAPVIEWS      0x28

#define VADTYPE_IMAGE  2
#define VADTYPE_SHIFT  4
#define VADTYPE_MASK   0x7

// Resolved at runtime from RtlGetVersion in DriverEntry
static ULONG g_OffVadRoot = 0;

static void CheckVadControlArea(PEPROCESS Process, PVOID moduleBase, DEEP_TARGET* Target) {
    if (g_OffVadRoot == 0) { Target->DbgWsExStatus = 0xF; return; }

    PVOID* vadRootPtr = (PVOID*)((ULONG_PTR)Process + g_OffVadRoot);
    if (!g_MmIsAddressValid(vadRootPtr)) { Target->DbgWsExStatus = 0xA; return; }

    PVOID node            = *vadRootPtr;
    ULONG_PTR targetVpn   = (ULONG_PTR)moduleBase >> 12;
    BOOLEAN firstNode     = TRUE;
    int depth             = 0;

    if (!node) {
        Target->DbgWsExStatus   = 0xB;
        Target->DbgWsExLowShare = (unsigned long)targetVpn;
        return;
    }

    for (depth = 0; depth < 64 && node != NULL; depth++) {
        if (!g_MmIsAddressValid(node)) {
            Target->DbgWsExStatus   = 0xC;
            Target->DbgWsExValid    = (unsigned long)depth;
            Target->DbgWsExLowShare = (unsigned long)targetVpn;
            return;
        }

        ULONG     startVpn  = *(ULONG*)((ULONG_PTR)node + OFF_MMVAD_SHORT_STARTINGVPN);
        ULONG     endVpn    = *(ULONG*)((ULONG_PTR)node + OFF_MMVAD_SHORT_ENDINGVPN);
        UCHAR     startHigh = *(UCHAR*)((ULONG_PTR)node + OFF_MMVAD_SHORT_VPNHIGH_START);
        UCHAR     endHigh   = *(UCHAR*)((ULONG_PTR)node + OFF_MMVAD_SHORT_VPNHIGH_END);
        ULONG_PTR fullStart = ((ULONG_PTR)startHigh << 32) | startVpn;
        ULONG_PTR fullEnd   = ((ULONG_PTR)endHigh   << 32) | endVpn;

        if (firstNode) { Target->DbgWsExSample = startVpn; firstNode = FALSE; }

        if (targetVpn >= fullStart && targetVpn <= fullEnd) {
            Target->DbgWsExStatus = 0;

            ULONG vadFlags  = *(ULONG*)((ULONG_PTR)node + OFF_MMVAD_SHORT_FLAGS);
            ULONG vadFlags2 = *(ULONG*)((ULONG_PTR)node + 0x40);
            Target->DbgWsExValid    = vadFlags;
            Target->DbgWsExLowShare = vadFlags2;

            if (((vadFlags >> VADTYPE_SHIFT) & VADTYPE_MASK) != VADTYPE_IMAGE)
                Target->Flags |= DEEP_FLAG_SECTION_REMAP;

            // Walk to ControlArea to read MapViews count
            PVOID* pSub = (PVOID*)((ULONG_PTR)node + OFF_MMVAD_SUBSECTION);
            if (g_MmIsAddressValid(pSub) && *pSub) {
                PVOID sub = *pSub;
                if (g_MmIsAddressValid(sub)) {
                    PVOID* pCA = (PVOID*)((ULONG_PTR)sub + OFF_SUBSECTION_CONTROLAREA);
                    if (g_MmIsAddressValid(pCA) && *pCA) {
                        PVOID ca = *pCA;
                        if (g_MmIsAddressValid(ca)) {
                            ULONGLONG* pMV = (ULONGLONG*)((ULONG_PTR)ca + OFF_CONTROLAREA_MAPVIEWS);
                            if (g_MmIsAddressValid(pMV))
                                Target->DbgWsExSample = (unsigned long)*pMV;
                        }
                    }
                }
            }
            return;
        }

        PVOID* children = (PVOID*)node;
        node = (targetVpn < fullStart) ? children[0] : children[1];
    }

    Target->DbgWsExStatus   = (node == NULL) ? 0xD : 0xE;
    Target->DbgWsExValid    = (unsigned long)depth;
    Target->DbgWsExLowShare = (unsigned long)targetVpn;
}
