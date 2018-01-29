/**
 * peeko
 * Copyright (c) 2018 Daax Rynd. All rights reserved.
 *
 * @file ntos.h
 * @author Daax Rynd (daax)
 * @date 1/25/2018 
 */

#ifndef _NTOS_H_
#define _NTOS_H_

//! Useful macros
#define DEREF(type, var, offset) *(type*)((var) + (offset))
#define PAGE_GRANULARITY     0x1000
#define KB                   (PAGE_GRANULARITY >> 2)

//! All structure definitions and enumerations intended for use on Windows 10 x64 1703 (15063.850) and up.

//
// System and process enumeration definitions
//
// begin_enums
//
typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation = 0x0,
    SystemProcessorInformation = 0x1,
    SystemPerformanceInformation = 0x2,
    SystemTimeOfDayInformation = 0x3,
    SystemPathInformation = 0x4,
    SystemProcessInformation = 0x5,
    SystemCallCountInformation = 0x6,
    SystemDeviceInformation = 0x7,
    SystemProcessorPerformanceInformation = 0x8,
    SystemFlagsInformation = 0x9,
    SystemCallTimeInformation = 0xA,
    SystemModuleInformation = 0xB,
    SystemLocksInformation = 0xC,
    SystemStackTraceInformation = 0xD,
    SystemPagedPoolInformation = 0xE,
    SystemNonPagedPoolInformation = 0xF,
    SystemHandleInformation = 0x10,
    SystemObjectInformation = 0x11,
    SystemPageFileInformation = 0x12,
    SystemVdmInstemulInformation = 0x13,
    SystemVdmBopInformation = 0x14,
    SystemFileCacheInformation = 0x15,
    SystemPoolTagInformation = 0x16,
    SystemInterruptInformation = 0x17,
    SystemDpcBehaviorInformation = 0x18,
    SystemFullMemoryInformation = 0x19,
    SystemLoadGdiDriverInformation = 0x1A,
    SystemUnloadGdiDriverInformation = 0x1B,
    SystemTimeAdjustmentInformation = 0x1C,
    SystemSummaryMemoryInformation = 0x1D,
    SystemMirrorMemoryInformation = 0x1E,
    SystemPerformanceTraceInformation = 0x1F,
    SystemObsolete0 = 0x20,
    SystemExceptionInformation = 0x21,
    SystemCrashDumpStateInformation = 0x22,
    SystemKernelDebuggerInformation = 0x23,
    SystemContextSwitchInformation = 0x24,
    SystemRegistryQuotaInformation = 0x25,
    SystemExtendServiceTableInformation = 0x26,
    SystemPrioritySeperation = 0x27,
    SystemVerifierAddDriverInformation = 0x28,
    SystemVerifierRemoveDriverInformation = 0x29,
    SystemProcessorIdleInformation = 0x2A,
    SystemLegacyDriverInformation = 0x2B,
    SystemCurrentTimeZoneInformation = 0x2C,
    SystemLookasideInformation = 0x2D,
    SystemTimeSlipNotification = 0x2E,
    SystemSessionCreate = 0x2F,
    SystemSessionDetach = 0x30,
    SystemSessionInformation = 0x31,
    SystemRangeStartInformation = 0x32,
    SystemVerifierInformation = 0x33,
    SystemVerifierThunkExtend = 0x34,
    SystemSessionProcessInformation = 0x35,
    SystemLoadGdiDriverInSystemSpace = 0x36,
    SystemNumaProcessorMap = 0x37,
    SystemPrefetcherInformation = 0x38,
    SystemExtendedProcessInformation = 0x39,
    SystemRecommendedSharedDataAlignment = 0x3A,
    SystemComPlusPackage = 0x3B,
    SystemNumaAvailableMemory = 0x3C,
    SystemProcessorPowerInformation = 0x3D,
    SystemEmulationBasicInformation = 0x3E,
    SystemEmulationProcessorInformation = 0x3F,
    SystemExtendedHandleInformation = 0x40,
    SystemLostDelayedWriteInformation = 0x41,
    SystemBigPoolInformation = 0x42,
    SystemSessionPoolTagInformation = 0x43,
    SystemSessionMappedViewInformation = 0x44,
    SystemHotpatchInformation = 0x45,
    SystemObjectSecurityMode = 0x46,
    SystemWatchdogTimerHandler = 0x47,
    SystemWatchdogTimerInformation = 0x48,
    SystemLogicalProcessorInformation = 0x49,
    SystemWow64SharedInformationObsolete = 0x4A,
    SystemRegisterFirmwareTableInformationHandler = 0x4B,
    SystemFirmwareTableInformation = 0x4C,
    SystemModuleInformationEx = 0x4D,
    SystemVerifierTriageInformation = 0x4E,
    SystemSuperfetchInformation = 0x4F,
    SystemMemoryListInformation = 0x50,
    SystemFileCacheInformationEx = 0x51,
    SystemThreadPriorityClientIdInformation = 0x52,
    SystemProcessorIdleCycleTimeInformation = 0x53,
    SystemVerifierCancellationInformation = 0x54,
    SystemProcessorPowerInformationEx = 0x55,
    SystemRefTraceInformation = 0x56,
    SystemSpecialPoolInformation = 0x57,
    SystemProcessIdInformation = 0x58,
    SystemErrorPortInformation = 0x59,
    SystemBootEnvironmentInformation = 0x5A,
    SystemHypervisorInformation = 0x5B,
    SystemVerifierInformationEx = 0x5C,
    SystemTimeZoneInformation = 0x5D,
    SystemImageFileExecutionOptionsInformation = 0x5E,
    SystemCoverageInformation = 0x5F,
    SystemPrefetchPatchInformation = 0x60,
    SystemVerifierFaultsInformation = 0x61,
    SystemSystemPartitionInformation = 0x62,
    SystemSystemDiskInformation = 0x63,
    SystemProcessorPerformanceDistribution = 0x64,
    SystemNumaProximityNodeInformation = 0x65,
    SystemDynamicTimeZoneInformation = 0x66,
    SystemCodeIntegrityInformation = 0x67,
    SystemProcessorMicrocodeUpdateInformation = 0x68,
    SystemProcessorBrandString = 0x69,
    SystemVirtualAddressInformation = 0x6A,
    SystemLogicalProcessorAndGroupInformation = 0x6B,
    SystemProcessorCycleTimeInformation = 0x6C,
    SystemStoreInformation = 0x6D,
    SystemRegistryAppendString = 0x6E,
    SystemAitSamplingValue = 0x6F,
    SystemVhdBootInformation = 0x70,
    SystemCpuQuotaInformation = 0x71,
    SystemNativeBasicInformation = 0x72,
    SystemErrorPortTimeouts = 0x73,
    SystemLowPriorityIoInformation = 0x74,
    SystemBootEntropyInformation = 0x75,
    SystemVerifierCountersInformation = 0x76,
    SystemPagedPoolInformationEx = 0x77,
    SystemSystemPtesInformationEx = 0x78,
    SystemNodeDistanceInformation = 0x79,
    SystemAcpiAuditInformation = 0x7A,
    SystemBasicPerformanceInformation = 0x7B,
    SystemQueryPerformanceCounterInformation = 0x7C,
    SystemSessionBigPoolInformation = 0x7D,
    SystemBootGraphicsInformation = 0x7E,
    SystemScrubPhysicalMemoryInformation = 0x7F,
    SystemBadPageInformation = 0x80,
    SystemProcessorProfileControlArea = 0x81,
    SystemCombinePhysicalMemoryInformation = 0x82,
    SystemEntropyInterruptTimingInformation = 0x83,
    SystemConsoleInformation = 0x84,
    SystemPlatformBinaryInformation = 0x85,
    SystemPolicyInformation = 0x86,
    SystemHypervisorProcessorCountInformation = 0x87,
    SystemDeviceDataInformation = 0x88,
    SystemDeviceDataEnumerationInformation = 0x89,
    SystemMemoryTopologyInformation = 0x8A,
    SystemMemoryChannelInformation = 0x8B,
    SystemBootLogoInformation = 0x8C,
    SystemProcessorPerformanceInformationEx = 0x8D,
    SystemSpare0 = 0x8E,
    SystemSecureBootPolicyInformation = 0x8F,
    SystemPageFileInformationEx = 0x90,
    SystemSecureBootInformation = 0x91,
    SystemEntropyInterruptTimingRawInformation = 0x92,
    SystemPortableWorkspaceEfiLauncherInformation = 0x93,
    SystemFullProcessInformation = 0x94,
    SystemKernelDebuggerInformationEx = 0x95,
    SystemBootMetadataInformation = 0x96,
    SystemSoftRebootInformation = 0x97,
    SystemElamCertificateInformation = 0x98,
    SystemOfflineDumpConfigInformation = 0x99,
    SystemProcessorFeaturesInformation = 0x9A,
    SystemRegistryReconciliationInformation = 0x9B,
    SystemEdidInformation = 0x9C,
    SystemManufacturingInformation = 0x9D,
    SystemEnergyEstimationConfigInformation = 0x9E,
    SystemHypervisorDetailInformation = 0x9F,
    SystemProcessorCycleStatsInformation = 0xA0,
    SystemVmGenerationCountInformation = 0xA1,
    SystemTrustedPlatformModuleInformation = 0xA2,
    SystemKernelDebuggerFlags = 0xA3,
    SystemCodeIntegrityPolicyInformation = 0xA4,
    SystemIsolatedUserModeInformation = 0xA5,
    SystemHardwareSecurityTestInterfaceResultsInformation = 0xA6,
    SystemSingleModuleInformation = 0xA7,
    SystemAllowedCpuSetsInformation = 0xA8,
    SystemDmaProtectionInformation = 0xA9,
    SystemInterruptCpuSetsInformation = 0xAA,
    SystemSecureBootPolicyFullInformation = 0xAB,
    SystemCodeIntegrityPolicyFullInformation = 0xAC,
    SystemAffinitizedInterruptProcessorInformation = 0xAD,
    SystemRootSiloInformation = 0xAE,
    SystemCpuSetInformation = 0xAF,
    SystemCpuSetTagInformation = 0xB0,
    SystemWin32WerStartCallout = 0xB1,
    SystemSecureKernelProfileInformation = 0xB2,
    MaxSystemInfoClass = 0xB3,
} SYSTEM_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation = 0x0,
    ProcessQuotaLimits = 0x1,
    ProcessIoCounters = 0x2,
    ProcessVmCounters = 0x3,
    ProcessTimes = 0x4,
    ProcessBasePriority = 0x5,
    ProcessRaisePriority = 0x6,
    ProcessDebugPort = 0x7,
    ProcessExceptionPort = 0x8,
    ProcessAccessToken = 0x9,
    ProcessLdtInformation = 0xA,
    ProcessLdtSize = 0xB,
    ProcessDefaultHardErrorMode = 0xC,
    ProcessIoPortHandlers = 0xD,
    ProcessPooledUsageAndLimits = 0xE,
    ProcessWorkingSetWatch = 0xF,
    ProcessUserModeIOPL = 0x10,
    ProcessEnableAlignmentFaultFixup = 0x11,
    ProcessPriorityClass = 0x12,
    ProcessWx86Information = 0x13,
    ProcessHandleCount = 0x14,
    ProcessAffinityMask = 0x15,
    ProcessPriorityBoost = 0x16,
    ProcessDeviceMap = 0x17,
    ProcessSessionInformation = 0x18,
    ProcessForegroundInformation = 0x19,
    ProcessWow64Information = 0x1A,
    ProcessImageFileName = 0x1B,
    ProcessLUIDDeviceMapsEnabled = 0x1C,
    ProcessBreakOnTermination = 0x1D,
    ProcessDebugObjectHandle = 0x1E,
    ProcessDebugFlags = 0x1F,
    ProcessHandleTracing = 0x20,
    ProcessIoPriority = 0x21,
    ProcessExecuteFlags = 0x22,
    ProcessTlsInformation = 0x23,
    ProcessCookie = 0x24,
    ProcessImageInformation = 0x25,
    ProcessCycleTime = 0x26,
    ProcessPagePriority = 0x27,
    ProcessInstrumentationCallback = 0x28,
    ProcessThreadStackAllocation = 0x29,
    ProcessWorkingSetWatchEx = 0x2A,
    ProcessImageFileNameWin32 = 0x2B,
    ProcessImageFileMapping = 0x2C,
    ProcessAffinityUpdateMode = 0x2D,
    ProcessMemoryAllocationMode = 0x2E,
    ProcessGroupInformation = 0x2F,
    ProcessTokenVirtualizationEnabled = 0x30,
    ProcessOwnerInformation = 0x31,
    ProcessWindowInformation = 0x32,
    ProcessHandleInformation = 0x33,
    ProcessMitigationPolicy = 0x34,
    ProcessDynamicFunctionTableInformation = 0x35,
    ProcessHandleCheckingMode = 0x36,
    ProcessKeepAliveCount = 0x37,
    ProcessRevokeFileHandles = 0x38,
    ProcessWorkingSetControl = 0x39,
    ProcessHandleTable = 0x3A,
    ProcessCheckStackExtentsMode = 0x3B,
    ProcessCommandLineInformation = 0x3C,
    ProcessProtectionInformation = 0x3D,
    ProcessMemoryExhaustion = 0x3E,
    ProcessFaultInformation = 0x3F,
    ProcessTelemetryIdInformation = 0x40,
    ProcessCommitReleaseInformation = 0x41,
    ProcessDefaultCpuSetsInformation = 0x42,
    ProcessAllowedCpuSetsInformation = 0x43,
    ProcessReserved1Information = 0x42,
    ProcessReserved2Information = 0x43,
    ProcessSubsystemProcess = 0x44,
    ProcessJobMemoryInformation = 0x45,
    ProcessInPrivate = 0x46,
    ProcessRaiseUMExceptionOnInvalidHandleClose = 0x47,
    MaxProcessInfoClass = 0x48,
} PROCESSINFOCLASS;

typedef enum _PROCESS_ENERGY_COMPONENT_TYPE_NUM
{
    PsEnergyComponentTypeCpu = 0x0,
    PsEnergyComponentTypeStorage = 0x1,
    PsEnergyComponentTypeNetwork = 0x2,
    PsEnergyComponentTypeMBB = 0x3,
    PsEnergyComponentTypeForegroundTime = 0x4,
    PsEnergyComponentTypePixelTime = 0x5,
    PsEnergyComponentTypeMax = 0x6,
} PROCESS_ENERGY_COMPONENT_TYPE_NUM;

typedef enum _PROCESS_WORKING_SET_OPERATION
{
    ProcessWorkingSetSwap = 0x0,
    ProcessWorkingSetEmpty = 0x1,
    ProcessWorkingSetOperationMax = 0x2,
} PROCESS_WORKING_SET_OPERATION;

typedef enum _PROCESS_TLS_INFORMATION_TYPE
{
    ProcessTlsReplaceIndex = 0x0,
    ProcessTlsReplaceVector = 0x1,
    MaxProcessTlsOperation = 0x2,
} PROCESS_TLS_INFORMATION_TYPE;

typedef enum _SYSTEM_VA_TYPE
{
    SystemVaTypeAll = 0x0,
    SystemVaTypeNonPagedPool = 0x1,
    SystemVaTypePagedPool = 0x2,
    SystemVaTypeSystemCache = 0x3,
    SystemVaTypeSystemPtes = 0x4,
    SystemVaTypeSessionSpace = 0x5,
    SystemVaTypeMax = 0x6,
} SYSTEM_VA_TYPE;

typedef enum _OBJECT_INFORMATION_CLASS
{
    ObjectBasicInformation = 0x0,
    ObjectNameInformation = 0x1,
    ObjectTypeInformation = 0x2,
    ObjectTypesInformation = 0x3,
    ObjectHandleFlagInformation = 0x4,
    ObjectSessionInformation = 0x5,
    MaxObjectInfoClass = 0x6,
} OBJECT_INFORMATION_CLASS;

typedef enum _LDR_DLL_LOAD_REASON
{
    LoadReasonStaticDependency = 0x0,
    LoadReasonStaticForwarderDependency = 0x1,
    LoadReasonDynamicForwarderDependency = 0x2,
    LoadReasonDelayloadDependency = 0x3,
    LoadReasonDynamicLoad = 0x4,
    LoadReasonAsImageLoad = 0x5,
    LoadReasonAsDataLoad = 0x6,
    LoadReasonUnknown = 0xFFFFFFFF,
} LDR_DLL_LOAD_REASON;

typedef enum _LDR_DDAG_STATE
{
    LdrModulesMerged = 0xFFFFFFFB,
    LdrModulesInitError = 0xFFFFFFFC,
    LdrModulesSnapError = 0xFFFFFFFD,
    LdrModulesUnloaded = 0xFFFFFFFE,
    LdrModulesUnloading = 0xFFFFFFFF,
    LdrModulesPlaceHolder = 0x0,
    LdrModulesMapping = 0x1,
    LdrModulesMapped = 0x2,
    LdrModulesWaitingForDependencies = 0x3,
    LdrModulesSnapping = 0x4,
    LdrModulesSnapped = 0x5,
    LdrModulesCondensed = 0x6,
    LdrModulesReadyToInit = 0x7,
    LdrModulesInitializing = 0x8,
    LdrModulesReadyToRun = 0x9,
} LDR_DDAG_STATE;

typedef enum _SECTION_INFORMATION_CLASS
{
    SectionBasicInformation = 0x0,
    SectionImageInformation = 0x1,
    SectionRelocationInformation = 0x2,
    MaxSectionInfoClass = 0x3,
} SECTION_INFORMATION_CLASS;

typedef enum _THREADINFOCLASS
{
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    ThreadBreakOnTermination,
    ThreadSwitchLegacyState,
    ThreadIsTerminated,
    ThreadLastSystemCall,
    ThreadIoPriority,
    ThreadCycleTime,
    ThreadPagePriority,
    ThreadActualBasePriority,
    ThreadTebInformation,
    ThreadCSwitchMon,
    ThreadCSwitchPmu,
    ThreadWow64Context,
    ThreadGroupInformation,
    ThreadUmsInformation,
    ThreadCounterProfiling,
    ThreadIdealProcessorEx,
    ThreadCpuAccountingInformation,
    ThreadSuspendCount,
    ThreadHeterogeneousCpuPolicy,
    ThreadContainerId,
    ThreadNameInformation,
    ThreadProperty,
    ThreadSelectedCpuSets,
    ThreadSystemThreadInformation,
    MaxThreadInfoClass
} THREADINFOCLASS;

typedef enum _SECTION_INHERIT {
    ViewShare,
    ViewUnmap
} SECTION_INHERIT;

typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS
{
    VmPrefetchInformation,
    VmPagePriorityInformation,
    VmCfgCallTargetInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS;

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

// end_enums

//
// Requires system and process structures
//
// begin_structs
//

typedef struct _PEB_LDR_DATA
{
    unsigned int Length;
    char Initialized;
    void *SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    void *EntryInProgress;
    char ShutdownInProgress;
    void *ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB_LDR_DATA32
{
    ULONG Length;
    UCHAR Initialized;
    ULONG SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
    ULONG EntryInProgress;
    UCHAR ShutdownInProgress;
    ULONG ShutdownThreadId;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    unsigned __int16 Flags;
    unsigned __int16 Length;
    unsigned int TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    void *Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    unsigned int MaximumLength;
    unsigned int Length;
    unsigned int Flags;
    unsigned int DebugFlags;
    void *ConsoleHandle;
    unsigned int ConsoleFlags;
    void *StandardInput;
    void *StandardOutput;
    void *StandardError;
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    void *Environment;
    unsigned int StartingX;
    unsigned int StartingY;
    unsigned int CountX;
    unsigned int CountY;
    unsigned int CountCharsX;
    unsigned int CountCharsY;
    unsigned int FillAttribute;
    unsigned int WindowFlags;
    unsigned int ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
    unsigned __int64 EnvironmentSize;
    unsigned __int64 EnvironmentVersion;
    void *PackageDependencyData;
    unsigned int ProcessGroupId;
    unsigned int LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB
{
    char InheritedAddressSpace;
    char ReadImageFileExecOptions;
    char BeingDebugged;

    union
    {
        char BitField;
        struct
        {
            __int8 ImageUsesLargePages : 1;
            __int8 IsProtectedProcess : 1;
            __int8 IsImageDynamicallyRelocated : 1;
            __int8 SkipPatchingUser32Forwarders : 1;
            __int8 IsPackagedProcess : 1;
            __int8 IsAppContainer : 1;
            __int8 IsProtectedProcessLight : 1;
            __int8 SpareBits : 1;
        };
    };

    char Padding0[4];

    void *Mutant;
    void *ImageBaseAddress;
    PEB_LDR_DATA *Ldr;
    RTL_USER_PROCESS_PARAMETERS *ProcessParameters;
    void *SubSystemData;
    void *ProcessHeap;
    RTL_CRITICAL_SECTION *FastPebLock;
    void *AtlThunkSListPtr;
    void *IFEOKey;

    union
    {
        unsigned int CrossProcessFlags;
        struct
        {
            unsigned __int32 ProcessInJob : 1;
            unsigned __int32 ProcessInitializing : 1;
            unsigned __int32 ProcessUsingVEH : 1;
            unsigned __int32 ProcessUsingVCH : 1;
            unsigned __int32 ProcessUsingFTH : 1;
            unsigned __int32 ReservedBits0 : 27;
        };
    };

    char Padding1[4];

    union
    {
        void *KernelCallbackTable;
        void *UserSharedInfoPtr;
    };

    unsigned int SystemReserved[1];
    unsigned int AtlThunkSListPtr32;
    void *ApiSetMap;
    unsigned int TlsExpansionCounter;
    char Padding2[4];
    void *TlsBitmap;
    unsigned int TlsBitmapBits[2];
    void *ReadOnlySharedMemoryBase;
    void *SparePvoid0;
    void **ReadOnlyStaticServerData;
    void *AnsiCodePageData;
    void *OemCodePageData;
    void *UnicodeCaseTableData;
    unsigned int NumberOfProcessors;
    unsigned int NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    unsigned __int64 HeapSegmentReserve;
    unsigned __int64 HeapSegmentCommit;
    unsigned __int64 HeapDeCommitTotalFreeThreshold;
    unsigned __int64 HeapDeCommitFreeBlockThreshold;
    unsigned int NumberOfHeaps;
    unsigned int MaximumNumberOfHeaps;
    void **ProcessHeaps;
    void *GdiSharedHandleTable;
    void *ProcessStarterHelper;
    unsigned int GdiDCAttributeList;
    char Padding3[4];
    RTL_CRITICAL_SECTION *LoaderLock;
    unsigned int OSMajorVersion;
    unsigned int OSMinorVersion;
    unsigned __int16 OSBuildNumber;
    unsigned __int16 OSCSDVersion;
    unsigned int OSPlatformId;
    unsigned int ImageSubsystem;
    unsigned int ImageSubsystemMajorVersion;
    unsigned int ImageSubsystemMinorVersion;
    char Padding4[4];
    unsigned __int64 ActiveProcessAffinityMask;
    unsigned int GdiHandleBuffer[60];
    void(__cdecl *PostProcessInitRoutine)();
    void *TlsExpansionBitmap;
    unsigned int TlsExpansionBitmapBits[32];
    unsigned int SessionId;
    char Padding5[4];
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    void *pShimData;
    void *AppCompatInfo;
    UNICODE_STRING CSDVersion;
    void *ActivationContextData;
    void *ProcessAssemblyStorageMap;
    void *SystemDefaultActivationContextData;
    void *SystemAssemblyStorageMap;
    unsigned __int64 MinimumStackCommit;
    void *FlsCallback;
    LIST_ENTRY FlsListHead;
    void *FlsBitmap;
    unsigned int FlsBitmapBits[4];
    unsigned int FlsHighIndex;
    void *WerRegistrationData;
    void *WerShipAssertPtr;
    void *pUnused;
    void *pImageHeaderHash;

    union
    {
        unsigned int TracingFlags;
        struct
        {
            unsigned __int32 HeapTracingEnabled : 1;
            unsigned __int32 CritSecTracingEnabled : 1;
            unsigned __int32 LibLoaderTracingEnabled : 1;
            unsigned __int32 SpareTracingBits : 29;
        };
    };

    char Padding6[4];
    unsigned __int64 CsrServerReadOnlySharedMemoryBase;
    unsigned __int64 TppWorkerpListLock;
    LIST_ENTRY TppWorkerpList;
    void *WaitOnAddressHashTable[128];
} PEB, *PPEB;

typedef struct _PEB32
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    union {
        UCHAR BitField;
        struct {
            UCHAR ImageUsesLargePages : 1;
            UCHAR IsProtectedProcess : 1;
            UCHAR IsImageDynamicallyRelocated : 1;
            UCHAR SkipPatchingUser32Forwarders : 1;
            UCHAR IsPackagedProcess : 1;
            UCHAR IsAppContainer : 1;
            UCHAR IsProtectedProcessLight : 1;
            UCHAR IsLongPathAwareProcess : 1;
        };
    };
    ULONG Mutant;
    ULONG ImageBaseAddress;
    ULONG Ldr;
    ULONG ProcessParameters;
    ULONG SubSystemData;
    ULONG ProcessHeap;
    ULONG FastPebLock;
    ULONG AtlThunkSListPtr;
    ULONG IFEOKey;
    union {
        ULONG CrossProcessFlags;
        struct {
            UCHAR ProcessInJob : 1;
            UCHAR ProcessInitializing : 1;
            UCHAR ProcessUsingVEH : 1;
            UCHAR ProcessUsingVCH : 1;
            UCHAR ProcessUsingFTH : 1;
            UCHAR ProcessPreviouslyThrottled : 1;
            UCHAR ProcessCurrentlyThrottled : 1;
            ULONG ReservedBits0 : 25;
        };
    };
    union {
        ULONG KernelCallbackTable;
        ULONG UserSharedInfoPtr;
    };
    ULONG SystemReserved[1];
    ULONG AtlThunkSListPtr32;
    ULONG ApiSetMap;
    ULONG TlsExpansionCounter;
    ULONG TlsBitmap;
    ULONG TlsBitmapBits[2];
    ULONG ReadOnlySharedMemoryBase;
    ULONG SharedData;
    ULONG ReadOnlyStaticServerData;
    ULONG AnsiCodePageData;
    ULONG OemCodePageData;
    ULONG UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG HeapSegmentReserve;
    ULONG HeapSegmentCommit;
    ULONG HeapDeCommitTotalFreeThreshold;
    ULONG HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    ULONG ProcessHeaps;
    ULONG GdiSharedHandleTable;
    ULONG ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    ULONG LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG ActiveProcessAffinityMask;
    ULONG GdiHandleBuffer[34];
    ULONG PostProcessInitRoutine;
    ULONG TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];
    ULONG SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    ULONG pShimData;
    ULONG AppCompatInfo;
    UNICODE_STRING CSDVersion;
    ULONG ActivationContextData;
    ULONG ProcessAssemblyStorageMap;
    ULONG SystemDefaultActivationContextData;
    ULONG SystemAssemblyStorageMap;
    ULONG MinimumStackCommit;
    ULONG FlsCallback;
    LIST_ENTRY FlsListHead;
    ULONG FlsBitmap;
    ULONG FlsBitmapBits[4];
    ULONG FlsHighIndex;
    ULONG WerRegistrationData;
    ULONG WerShipAssertPtr;
    ULONG pUnused;
    ULONG pImageHeaderHash;
    union {
        ULONG TracingFlags;
        struct {
            UCHAR HeapTracingEnabled : 1;
            UCHAR CritSecTracingEnabled : 1;
            UCHAR LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
    ULONG TppWorkerpListLock;
    LIST_ENTRY TppWorkerpList;
    ULONG WaitOnAddressHashTable[128];
} PEB32, *PPEB32;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    SIZE_T DllBase;
    SIZE_T EntryPoint;
    unsigned int SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        char FlagGroup[4];
        unsigned int Flags;
        struct
        {
            unsigned __int32 PackagedBinary : 1;
            unsigned __int32 MarkedForRemoval : 1;
            unsigned __int32 ImageDll : 1;
            unsigned __int32 LoadNotificationsSent : 1;
            unsigned __int32 TelemetryEntryProcessed : 1;
            unsigned __int32 ProcessStaticImport : 1;
            unsigned __int32 InLegacyLists : 1;
            unsigned __int32 InIndexes : 1;
            unsigned __int32 ShimDll : 1;
            unsigned __int32 InExceptionTable : 1;
            unsigned __int32 ReservedFlags1 : 2;
            unsigned __int32 LoadInProgress : 1;
            unsigned __int32 LoadConfigProcessed : 1;
            unsigned __int32 EntryProcessed : 1;
            unsigned __int32 ProtectDelayLoad : 1;
            unsigned __int32 ReservedFlags3 : 2;
            unsigned __int32 DontCallForThreads : 1;
            unsigned __int32 ProcessAttachCalled : 1;
            unsigned __int32 ProcessAttachFailed : 1;
            unsigned __int32 CorDeferredValidate : 1;
            unsigned __int32 CorImage : 1;
            unsigned __int32 DontRelocate : 1;
            unsigned __int32 CorILOnly : 1;
            unsigned __int32 ReservedFlags5 : 3;
            unsigned __int32 Redirected : 1;
            unsigned __int32 ReservedFlags6 : 2;
            unsigned __int32 CompatDatabaseProcessed : 1;
        };
    };

    //
    // Unnecessary fields redacted
    //
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    ULONG DllBase;
    ULONG EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _PROCESS_BASIC_INFORMATION
{
    int ExitStatus;
    PEB *PebBaseAddress;
    unsigned __int64 AffinityMask;
    int BasePriority;
    unsigned __int64 UniqueProcessId;
    unsigned __int64 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

// end_structs

//
// Required system routines
//

NTSTATUS WINAPI ZwQuerySystemInformation(
    _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Inout_   PVOID SystemInformation,
    _In_      ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

NTSTATUS WINAPI ZwQueryInformationProcess(
    _In_      HANDLE ProcessHandle,
    _In_      PROCESSINFOCLASS ProcessInformationClass,
    _Out_     PVOID ProcessInformation,
    _In_      ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
);

NTSTATUS WINAPI ZwQueryInformationThread(
    _In_      HANDLE ThreadHandle,
    _In_      THREADINFOCLASS ThreadInformationClass,
    _In_      PVOID ThreadInformation,
    _In_      ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
);

NTSTATUS WINAPI ZwQueryVirtualMemory(
    _In_      HANDLE ProcessHandle,
    _In_opt_  PVOID BaseAddress,
    _In_      MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_     PVOID MemoryInformation,
    _In_      SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
);

NTSTATUS WINAPI ZwQueryObject(
    _In_opt_  HANDLE Handle,
    _In_      OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _Out_opt_ PVOID ObjectInformation,
    _In_      ULONG ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength
);

NTSTATUS WINAPI ZwAllocateVirtualMemory(
    _In_    HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _In_    ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_    ULONG AllocationType,
    _In_    ULONG Protect
);

NTSTATUS WINAPI ZwProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _In_ SIZE_T NumberOfBytes,
    _In_ SIZE_T ProtectionMask,
    _Out_ PSIZE_T OldProtection
);

NTSTATUS WINAPI ZwFreeVirtualMemory(
    _In_    HANDLE  ProcessHandle,
    _Inout_ PVOID   *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_    ULONG   FreeType
);

NTSTATUS WINAPI ZwMapViewOfSection(
    _In_        HANDLE SectionHandle,
    _In_        HANDLE ProcessHandle,
    _Inout_     PVOID *BaseAddress,
    _In_        ULONG_PTR ZeroBits,
    _In_        SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER  SectionOffset,
    _Inout_     PSIZE_T ViewSize,
    _In_        SECTION_INHERIT InheritDisposition,
    _In_        ULONG AllocationType,
    _In_        ULONG Win32Protect
);

NTSTATUS WINAPI ZwUnmapViewOfSection(
    _In_     HANDLE ProcessHandle,
    _In_opt_ PVOID  BaseAddress
);

NTSTATUS WINAPI ZwOpenSection(
    _Out_ PHANDLE SectionHandle,
    _In_  ACCESS_MASK DesiredAccess,
    _In_  PVOID ObjectAttributes
);

NTSTATUS WINAPI ZwOpenProcess(
    _Out_    PHANDLE ProcessHandle,
    _In_     ACCESS_MASK DesiredAccess,
    _In_     PVOID ObjectAttributes,
    _In_opt_ PVOID ClientId
);

NTSTATUS WINAPI ZwSetSystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _In_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength
);

NTSTATUS WINAPI ZwSetInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG ProcessInfoClass,
    _In_ PVOID ProcessInfo,
    _In_ ULONG ProcessInfoLength
);

NTSTATUS WINAPI ZwSetInformationObject(
    _In_ HANDLE ObjectHandle,
    _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _In_ PVOID ObjectInformation,
    _In_ ULONG Length
);

NTSTATUS WINAPI ZwSetInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _In_ PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength
);

NTSTATUS WINAPI ZwSetInformationVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_ VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
    _In_ ULONG_PTR NumberOfEntries,
    _In_ PVOID VirtualAddresses,
    _In_ PVOID VmInformation,
    _In_ ULONG VmInformationLength
);

NTSTATUS WINAPI ZwDuplicateObject(
    _In_ HANDLE SourceProcessHandle,
    _In_ HANDLE SourceHandle,
    _In_opt_ HANDLE TargetProcessHandle,
    _Out_opt_ PHANDLE TargetHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Options
);

NTSTATUS WINAPI ZwTerminateProcess(
    _In_opt_ HANDLE ProcessHandle,
    _In_ LONG ExitStatus
);

NTSTATUS WINAPI ZwTerminateThread(
    _In_opt_ HANDLE ThreadHandle,
    _In_ LONG ExitStatus
);

NTSTATUS WINAPI ZwClose(
    _In_ HANDLE Handle
);

NTSTATUS WINAPI ZwDelayExecution(
    _In_ BOOLEAN Alertable,
    _In_ PLARGE_INTEGER Interval
);

#endif // _NTOS_H_
