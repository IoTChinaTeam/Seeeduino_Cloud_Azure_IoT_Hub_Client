// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef WINCE
#include "iothubtransportmqtt.h"
#else
#include "iothubtransporthttp.h"
#endif
#include "schemalib.h"
#include "iothub_client.h"
#include "serializer.h"
#include "schemaserializer.h"
#include "azure_c_shared_utility/threadapi.h"
#include "azure_c_shared_utility/platform.h"

#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <ctype.h>

#ifdef MBED_BUILD_TIMESTAMP
#include "certs.h"
#endif // MBED_BUILD_TIMESTAMP


static char hostName[128] = { 0, };
static char deviceId[128] = { 0, };
static char deviceKey[128] = { 0, };
static char hubSuffix[128] = { 0, };

static char msgText[2048] = { 0, };
static char msgBuffer[2048] = { 0, };

static char g_firmwareVersion[16] = { 0 };
static int g_telemetryInterval = 5;
static IOTHUB_CLIENT_HANDLE g_iotHubClientHandle = NULL;

// Define the Model
BEGIN_NAMESPACE(Contoso);

DECLARE_STRUCT(SystemProperties,
    ascii_char_ptr, DeviceID,
    _Bool, Enabled
);

DECLARE_STRUCT(DeviceProperties,
ascii_char_ptr, DeviceID,
_Bool, HubEnabledState
);

DECLARE_MODEL(Thermostat,

    /* Event data */
    WITH_DATA(int, Temperature),
    WITH_DATA(int, Humidity),
    WITH_DATA(int, Light),
    WITH_DATA(int, Sound),
    WITH_DATA(ascii_char_ptr, DeviceId),

    /* Device Info - This is command metadata + some extra fields */
    WITH_DATA(ascii_char_ptr, ObjectType),
    WITH_DATA(_Bool, IsSimulatedDevice),
    WITH_DATA(ascii_char_ptr, Version),
    WITH_DATA(DeviceProperties, DeviceProperties),
    WITH_DATA(ascii_char_ptr_no_quotes, Commands),

    /* Commands implemented by the device */
    WITH_ACTION(SetTemperature, int, temperature),
    WITH_ACTION(SetHumidity, int, humidity),
    WITH_ACTION(SetLight, int, light),
    WITH_ACTION(SetSound, int, sound),
    WITH_ACTION(SetRGBLed, int, rgbled)
);

END_NAMESPACE(Contoso);

/* utilities region */
void AllocAndPrintf(unsigned char** buffer, size_t* size, const char* format, ...)
{
    va_list args;
    va_start(args, format);
    *size = vsnprintf(NULL, 0, format, args);
    va_end(args);

    *buffer = malloc(*size + 1);
    va_start(args, format);
    vsprintf((char*)*buffer, format, args);
    va_end(args);
}

void AllocAndVPrintf(unsigned char** buffer, size_t* size, const char* format, va_list argptr)
{
    *size = vsnprintf(NULL, 0, format, argptr);

    *buffer = malloc(*size + 1);
    vsprintf((char*)*buffer, format, argptr);
}

bool GetNumberFromString(const unsigned char* text, size_t size, int* pValue)
{
    const unsigned char* pStart = text;
    for (; pStart < text + size; pStart++)
    {
        if (isdigit(*pStart))
        {
            break;
        }
    }

    const unsigned char* pEnd = pStart + 1;
    for (; pEnd <= text + size; pEnd++)
    {
        if (!isdigit(*pEnd))
        {
            break;
        }
    }

    if (pStart >= text + size)
    {
        return false;
    }

    unsigned char buffer[16] = { 0 };
    strncpy(buffer, pStart, pEnd - pStart);

    *pValue = atoi(buffer);
    return true;
}

char* FormatTime(time_t* time)
{
    static char buffer[128];

    struct tm* p = gmtime(time);

    sprintf(buffer, "%04d-%02d-%02dT%02d:%02d:%02dZ",
        p->tm_year + 1900,
        p->tm_mon + 1,
        p->tm_mday,
        p->tm_hour,
        p->tm_min,
        p->tm_sec);

    return buffer;
}
/* utilities region end */

static void ReceivedMessageSave(char *buffer)
{
    FILE *fpConfig;

    if (NULL == (fpConfig = fopen("AzureMessageReceive", "w")))
    {
        printf("Open azure message content file fail.\r\n");
    }
    else
    {
        fwrite(buffer, 1, strlen(buffer), fpConfig);
        fclose(fpConfig);
    }
}

EXECUTE_COMMAND_RESULT SetTemperature(Thermostat* thermostat, int temperature)
{
    char data[128] = { 0, };
    snprintf(data, sizeof(data), "\"SetTemperature\":%d", temperature);
    (void)printf("%s\r\n", data);
    ReceivedMessageSave(data);
    return EXECUTE_COMMAND_SUCCESS;
}

EXECUTE_COMMAND_RESULT SetHumidity(Thermostat* thermostat, int humidity)
{
    char data[128] = { 0, };
    snprintf(data, sizeof(data), "\"SetHumidity\":%d", humidity);
    (void)printf("%s\r\n", data);
    ReceivedMessageSave(data);
    return EXECUTE_COMMAND_SUCCESS;
}

EXECUTE_COMMAND_RESULT SetLight(Thermostat* thermostat, int light)
{
    char data[128] = { 0, };
    snprintf(data, sizeof(data), "\"SetLight\":%d", light);
    (void)printf("%s\r\n", data);
    ReceivedMessageSave(data);
    return EXECUTE_COMMAND_SUCCESS;
}

EXECUTE_COMMAND_RESULT SetSound(Thermostat* thermostat, int sound)
{
    char data[128] = { 0, };
    snprintf(data, sizeof(data), "\"SetSound\":%d", sound);
    (void)printf("%s\r\n", data);
    ReceivedMessageSave(data);
    return EXECUTE_COMMAND_SUCCESS;
}

EXECUTE_COMMAND_RESULT SetRGBLed(Thermostat* thermostat, int rgbled)
{
    char data[128] = { 0, };
    snprintf(data, sizeof(data), "\"SetRGBLed\":%d", rgbled);
    (void)printf("%s\r\n", data);
    ReceivedMessageSave(data);
    return EXECUTE_COMMAND_SUCCESS;
}

static void SendConfirmationCallback(IOTHUB_CLIENT_CONFIRMATION_RESULT result, void* userContextCallback)
{
    FILE *fpConfig;
    char data[128] = { 0, };

    snprintf(data, sizeof(data), "%s", ENUM_TO_STRING(IOTHUB_CLIENT_CONFIRMATION_RESULT, result));
    (void)printf(data);

    if (NULL == (fpConfig = fopen("run.log", "w")))
    {
        printf("Open log file fail.\r\n");
    }
    else
    {
        fwrite(data, 1, strlen(data), fpConfig);
        fclose(fpConfig);
    }
}

static void sendMessage(IOTHUB_CLIENT_HANDLE iotHubClientHandle, const unsigned char* buffer, size_t size)
{
    IOTHUB_MESSAGE_HANDLE messageHandle = IoTHubMessage_CreateFromByteArray(buffer, size);
    if (messageHandle == NULL)
    {
        printf("unable to create a new IoTHubMessage\r\n");
    }
    else
    {
        if (IoTHubClient_SendEventAsync(iotHubClientHandle, messageHandle, NULL, NULL) != IOTHUB_CLIENT_OK)
        {
            printf("failed to hand over the message to IoTHubClient");
        }
        else
        {
            printf("IoTHubClient accepted the message for delivery\r\n");
        }

        IoTHubMessage_Destroy(messageHandle);
    }
    free((void*)buffer);
}

/*this function "links" IoTHub to the serialization library*/
static IOTHUBMESSAGE_DISPOSITION_RESULT IoTHubMessage(IOTHUB_MESSAGE_HANDLE message, void* userContextCallback)
{
    FILE *fpConfig;

    IOTHUBMESSAGE_DISPOSITION_RESULT result;
    const unsigned char* buffer;
    size_t size;

    if (IoTHubMessage_GetByteArray(message, &buffer, &size) != IOTHUB_MESSAGE_OK)
    {
        printf("unable to IoTHubMessage_GetByteArray\r\n");
        result = EXECUTE_COMMAND_ERROR;
    }
    else
    {
        if (NULL == (fpConfig = fopen("AzureMessageReceive", "w")))
        {
            printf("Open azure message content file fail.\r\n");
        }
        else
        {
            fwrite(buffer, 1, size, fpConfig);
            fclose(fpConfig);
        }

        /*buffer is not zero terminated*/
        char* temp = malloc(size + 1);
        if (temp == NULL)
        {
            printf("failed to malloc\r\n");
            result = EXECUTE_COMMAND_ERROR;
        }
        else
        {
            EXECUTE_COMMAND_RESULT executeCommandResult;

            memcpy(temp, buffer, size);
            temp[size] = '\0';
            executeCommandResult = EXECUTE_COMMAND(userContextCallback, temp);
            result =
                (executeCommandResult == EXECUTE_COMMAND_ERROR) ? IOTHUBMESSAGE_ABANDONED :
                (executeCommandResult == EXECUTE_COMMAND_SUCCESS) ? IOTHUBMESSAGE_ACCEPTED :
                IOTHUBMESSAGE_REJECTED;
            free(temp);
        }
    }
    return result;
}

static int getAccountInfo(char *buffer)
{
    int i, result = 1;
    char *ptr;

    ptr = strstr(buffer, "???");
    if (ptr)
    {
        result = 0;
        return result;
    }

    ptr = strstr(buffer, "HOST_NAME:");
    if (ptr)
    {
        i = 0;
        while (1)
        {
            if (i < sizeof(hostName))hostName[i++] = *(ptr + 10 + i);
            if (*(ptr + 10 + i) == '.' && *(ptr + 10 + i + 1) == 'a' && *(ptr + 10 + i + 2) == 'z' && *(ptr + 10 + i + 3) == 'u' && *(ptr + 10 + i + 4) == 'r' && *(ptr + 10 + i + 5) == 'e')break;
        }
        hostName[i] = '\0';
        printf("hostName is %s\r\n", hostName);
    }

    ptr = strstr(buffer, "azure-devices.");
    if (ptr)
    {
        i = 0;
        while (1)
        {
            if (i < sizeof(hubSuffix))hubSuffix[i++] = *(ptr + i);
            if (*(ptr + i) == '\n')break;
        }
        hubSuffix[i] = '\0';
        printf("hubSuffix is %s\r\n", hubSuffix);
    }

    ptr = strstr(buffer, "DEVICE_ID:");
    if (ptr)
    {
        i = 0;
        while (1)
        {
            if (i < sizeof(deviceId))deviceId[i++] = *(ptr + 10 + i);
            if (*(ptr + 10 + i) == '\n')break;
        }
        deviceId[i] = '\0';
        printf("deviceId is %s\r\n", deviceId);
    }

    ptr = strstr(buffer, "DEVICE_KEY:");
    if (ptr)
    {
        i = 0;
        while (1)
        {
            if (i < sizeof(deviceKey))deviceKey[i++] = *(ptr + 11 + i);
            if (*(ptr + 11 + i) == 0 || *(ptr + 11 + i) == '\n')break;
        }
        deviceKey[i] = '\0';
        printf("deviceKey is %s\r\n", deviceKey);
    }

    return result;
}

void LoadConfig()
{
    FILE* fp;

    strcpy(g_firmwareVersion, "0.1");
    if (NULL == (fp = fopen("firmwareVersion", "r")))
    {
        printf("Failed to open firmwareVersion file to read\r\n");
    }
    else
    {
        fgets(g_firmwareVersion, sizeof(g_firmwareVersion), fp);
        fclose(fp);
    }
    printf("Set firmwareVersion = %s\r\n", g_firmwareVersion);

    g_telemetryInterval = 15;
    if (NULL == (fp = fopen("telemetryInterval", "r")))
    {
        printf("Failed to open telemetryInterval file to read\r\n");
    }
    else
    {
        char buffer[16] = { 0 };
        fgets(buffer, sizeof(buffer), fp);
        fclose(fp);

        int telemetryInterval = atoi(buffer);
        if (telemetryInterval > 0)
        {
            g_telemetryInterval = telemetryInterval;
        }
    }
    printf("Set telemetry interval = %u\r\n", g_telemetryInterval);
}

void WriteConfig()
{
    FILE* fp;

    if (NULL == (fp = fopen("firmwareVersion", "w")))
    {
        printf("Failed to open firmwareVersion file to write\r\n");
    }
    else
    {
        fprintf(fp, g_firmwareVersion);
        fclose(fp);
    }

    if (NULL == (fp = fopen("telemetryInterval", "w")))
    {
        printf("Failed to open telemetryInterval file to write\r\n");
    }
    else
    {
        fprintf(fp, "%u", g_telemetryInterval);
        fclose(fp);
    }
}

void UpdateReportedProperties(const char* format, ...)
{
    unsigned char* report;
    size_t len;

    va_list args;
    va_start(args, format);
    AllocAndVPrintf(&report, &len, format, args);
    va_end(args);

    if (IoTHubClient_SendReportedState(g_iotHubClientHandle, report, len, NULL, NULL) != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to update reported properties: %.*s\r\n", len, report);
    }
    else
    {
        (void)printf("Succeeded in updating reported properties: %.*s\r\n", len, report);
    }

    free(report);
}

void ReportSystemProperties()
{
    struct sysinfo sysInfo;
    sysinfo(&sysInfo);

    struct utsname sysName;
    uname(&sysName);

    time_t now;
    time(&now);

    UpdateReportedProperties(
        "{ 'System': { 'InstalledRAM': '%u MB', 'Platform': '%s %s', 'FirmwareVersion': '%s' }, 'Device': { 'StartupTime': '%s' } }",
        sysInfo.totalram * sysInfo.mem_unit / 1024 / 1024,
        sysName.sysname,
        sysName.release,
        g_firmwareVersion,
        FormatTime(&now));
}

void ReportSupportedMethods()
{
    UpdateReportedProperties("{ 'SupportedMethods': { 'SetRGBLED--rgb-int': 'Set color of LED', 'InitiateFirmwareUpdate--FwPackageUri-string': 'Updates device Firmware. Use parameter FwPackageUri to specifiy the URI of the firmware file, e.g. https://iotrmassets.blob.core.windows.net/firmwares/FW20.bin' } }");
}

void ReportConfigProperties()
{
    UpdateReportedProperties(
        "{ 'Config': { 'TelemetryInterval': %d } }",
        g_telemetryInterval);
}

/* Device method handler region */
void OnMethodSetRGBLED(const unsigned char* payload, size_t size, unsigned char** response, size_t* resp_size)
{
    int rgb;
    if (!GetNumberFromString(payload, size, &rgb))
    {
        AllocAndPrintf(response, resp_size, "{ 'message': 'Invalid payload' }");
    }
    else
    {
        FILE* fp;
        if (NULL == (fp = fopen("AzureMessageReceive", "w")))
        {
            printf("Open azure message content file fail.\r\n");

            AllocAndPrintf(response, resp_size, "{ 'message': 'Open azure message content file fail' }");
        }
        else
        {
            fprintf(fp, "\"SetRGBLed\":%d", rgb);
            fclose(fp);

            AllocAndPrintf(response, resp_size, "{ 'message': 'Accepted, rgb = %d' }", rgb);
        }
    }
}

void* FirmwareUpdateThread(void* arg)
{
    time_t begin, end, stepBegin, stepEnd;
    int version = (int)arg;

    // Clear all reportes
    UpdateReportedProperties("{ 'Method' : { 'UpdateFirmware': null } }");

    time(&begin);
    UpdateReportedProperties(
        "{ 'Method' : { 'UpdateFirmware': { 'Duration-s': 0, 'LastUpdate': '%s', 'Status': 'Running' } } }",
        FormatTime(&begin));

    time(&stepBegin);
    UpdateReportedProperties(
        "{ 'Method' : { 'UpdateFirmware': { 'Download' : { 'Duration-s': 0, 'LastUpdate': '%s', 'Status': 'Running' } } } }",
        FormatTime(&stepBegin));

    ThreadAPI_Sleep(20000);

    time(&stepEnd);
    if (version <= 0)
    {
        UpdateReportedProperties(
            "{ 'Method' : { 'UpdateFirmware': { 'Download' : { 'Duration-s': %u, 'LastUpdate': '%s', 'Status': 'Failed' } } } }",
            stepEnd - stepBegin,
            FormatTime(&stepEnd));

        time(&end);
        UpdateReportedProperties(
            "{ 'Method' : { 'UpdateFirmware': { 'Duration-s': %u, 'LastUpdate': '%s', 'Status': 'Failed' } } }",
            end - begin,
            FormatTime(&end));

        return NULL;
    }
    else
    {
        UpdateReportedProperties(
            "{ 'Method' : { 'UpdateFirmware': { 'Download' : { 'Duration-s': %u, 'LastUpdate': '%s', 'Status': 'Complete' } } } }",
            stepEnd - stepBegin,
            FormatTime(&stepEnd));
    }

    time(&stepBegin);
    UpdateReportedProperties(
        "{ 'Method' : { 'UpdateFirmware': { 'Applied' : { 'Duration-s': 0, 'LastUpdate': '%s', 'Status': 'Running' } } } }",
        FormatTime(&stepBegin));

    ThreadAPI_Sleep(20000);

    time(&stepEnd);
    UpdateReportedProperties(
        "{ 'Method' : { 'UpdateFirmware': { 'Applied' : { 'Duration-s': %u, 'LastUpdate': '%s', 'Status': 'Complete' } } } }",
        stepEnd - stepBegin,
        FormatTime(&stepEnd));

    time(&stepBegin);
    UpdateReportedProperties(
        "{ 'Method' : { 'UpdateFirmware': { 'Reboot' : { 'Duration-s': 0, 'LastUpdate': '%s', 'Status': 'Running' } } } }",
        FormatTime(&stepBegin));

    ThreadAPI_Sleep(20000);

    time(&stepEnd);
    UpdateReportedProperties(
        "{ 'Method' : { 'UpdateFirmware': { 'Reboot' : { 'Duration-s': %u, 'LastUpdate': '%s', 'Status': 'Complete' } } } }",
        stepEnd - stepBegin,
        FormatTime(&stepEnd));

    time(&end);
    UpdateReportedProperties(
        "{ 'Method' : { 'UpdateFirmware': { 'Duration-s': %u, 'LastUpdate': '%s', 'Status': 'Complete' } } }",
        end - begin,
        FormatTime(&end));

    sprintf(g_firmwareVersion, "%d.%d", version / 10, version % 10);
    if (strcmp(g_firmwareVersion, "2.0") >= 0)
    {
        g_telemetryInterval = 5;
    }

    WriteConfig();

    UpdateReportedProperties(
        "{ 'System': { 'FirmwareVersion': '%s' }, 'Device': { 'StartupTime': '%s' }, 'Config': { 'TelemetryInterval': %u } }",
        g_firmwareVersion,
        FormatTime(&end),
        g_telemetryInterval);

    return NULL;
}

void OnMethodFirmwareUpdate(const unsigned char* payload, size_t size, unsigned char** response, size_t* resp_size)
{
    const unsigned char* key = "\"FwPackageUri\":";

    unsigned char* p = strstr(payload, key);
    if (p == NULL)
    {
        AllocAndPrintf(response, resp_size, "{ 'message': 'Invalid payload' }");
        return;
    }

    unsigned char* pStart = strchr(p + strlen(key), '\"');
    if (pStart == NULL)
    {
        AllocAndPrintf(response, resp_size, "{ 'message': 'Invalid payload' }");
        return;
    }

    unsigned char* pEnd = strchr(pStart + 1, '\"');
    if (pEnd == NULL)
    {
        AllocAndPrintf(response, resp_size, "{ 'message': 'Invalid payload' }");
        return;
    }

    unsigned char url[1024];
    strcpy(url, pStart + 1);
    url[pEnd - pStart - 1] = 0;
    printf("Updaing firmware with %s\r\n", url);
    AllocAndPrintf(response, resp_size, "{ 'message': 'Accepted, url = %s' }", url);

    int version;
    GetNumberFromString(url, strlen(url), &version);
    printf("Version = %d\r\n", version);

    pthread_t tid;
    pthread_create(&tid, NULL, &FirmwareUpdateThread, (void*)version);
}


int OnDeviceMethodInvoked(const char* method_name, const unsigned char* payload, size_t size, unsigned char** response, size_t* resp_size, void* userContextCallback)
{
    printf("Method call: name = %s, payload = %.*s\r\n", method_name, size, payload);

    if (strcmp(method_name, "SetRGBLED") == 0)
    {
        OnMethodSetRGBLED(payload, size, response, resp_size);
    }
    else if (strcmp(method_name, "InitiateFirmwareUpdate") == 0)
    {
        OnMethodFirmwareUpdate(payload, size, response, resp_size);
    }
    else
    {
        AllocAndPrintf(response, resp_size, "{'message': 'Unknown method %s'}", method_name);
    }

    return IOTHUB_CLIENT_OK;
}
/* Device method handler region end */

/* Property update handler region */
void OnDesiredTelemetryIntervalChanged(int telemetryInterval)
{
    g_telemetryInterval = telemetryInterval;

    WriteConfig();
    ReportConfigProperties();

    printf("Telemetry interval set to %u\r\n", g_telemetryInterval);
}

void OnDesiredPropertyChanged(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payload, size_t size, void* userContextCallback)
{
    printf("Property changed: %.*s\r\n", size, payload);

    UpdateReportedProperties(
        "{ 'Device': { 'LastDesiredPropertyChange': '%.*s' }}",
        size,
        payload);

    unsigned char *p = strstr(payload, "\"TelemetryInterval\":");

    int telemetryInterval;
    if (GetNumberFromString(p, size - (p - payload), &telemetryInterval) && telemetryInterval > 0)
    {
        OnDesiredTelemetryIntervalChanged(telemetryInterval);
    }
}
/* Property update handler region end */

void remote_monitoring_run(void)
{
    FILE *fpConfig;
    char *ptr;
    char i;

    while (1)
    {
        if (NULL == (fpConfig = fopen("AzureConnectionString", "r")))
        {
            printf("Open azure connection string file fail.\r\n");
        }
        else
        {
            if (0 == fread(msgText, 1, sizeof(msgText), fpConfig))
            {
                printf("Get connection string fail.\r\n");
            }
            else
            {
                printf("Load Azure Connection Sting ok.\r\n");
                fclose(fpConfig);

                if (getAccountInfo(msgText))
                {
                    printf("Azure Client Sting Form is right.\r\n");
                    break;
                }
                else
                {
                    printf("Azure Client Sting Form is error.\r\n");
                }
            }
        }

        ThreadAPI_Sleep(1000);
    }

    if (platform_init() != 0)
    {
        printf("Failed to initialize the platform.\r\n");
    }
    else
    {
        if (serializer_init(NULL) != SERIALIZER_OK)
        {
            printf("Failed on serializer_init\r\n");
        }
        else
        {
            IOTHUB_CLIENT_CONFIG config;
            IOTHUB_CLIENT_HANDLE iotHubClientHandle;

            memset(&config, 0, sizeof config);
            config.deviceId = deviceId;
            config.deviceKey = deviceKey;
            config.iotHubName = hostName;
            config.iotHubSuffix = hubSuffix;
#ifndef WINCE
            config.protocol = MQTT_Protocol;
#else
            config.protocol = HTTP_Protocol;
#endif
            iotHubClientHandle = IoTHubClient_Create(&config);
            g_iotHubClientHandle = iotHubClientHandle;

            if (iotHubClientHandle == NULL)
            {
                (void)printf("Failed on IoTHubClient_CreateFromConnectionString\r\n");
            }
            else
            {
#ifdef MBED_BUILD_TIMESTAMP
                // For mbed add the certificate information
                if (IoTHubClient_SetOption(iotHubClientHandle, "TrustedCerts", certificates) != IOTHUB_CLIENT_OK)
                {
                    printf("failure to set option \"TrustedCerts\"\r\n");
                }
#endif // MBED_BUILD_TIMESTAMP

                Thermostat* thermostat = CREATE_MODEL_INSTANCE(Contoso, Thermostat);
                if (thermostat == NULL)
                {
                    (void)printf("Failed on CREATE_MODEL_INSTANCE\r\n");
                }
                else
                {
                    STRING_HANDLE commandsMetadata;

                    if (IoTHubClient_SetMessageCallback(iotHubClientHandle, IoTHubMessage, thermostat) != IOTHUB_CLIENT_OK)
                    {
                        printf("unable to IoTHubClient_SetMessageCallback\r\n");
                    }
                    else if (IoTHubClient_SetDeviceMethodCallback(iotHubClientHandle, OnDeviceMethodInvoked, NULL) != IOTHUB_CLIENT_OK)
                    {
                        printf("unable to IoTHubClient_SetDeviceMethodCallback\r\n");
                    }
                    else if (IoTHubClient_SetDeviceTwinCallback(iotHubClientHandle, OnDesiredPropertyChanged, NULL) != IOTHUB_CLIENT_OK)
                    {
                        printf("unable to IoTHubClient_SetDeviceTwinCallback\r\n");
                    }
                    else
                    {
                        /* send the device info upon startup so that the cloud app knows
                        what commands are available and the fact that the device is up */
                        thermostat->ObjectType = "DeviceInfo";
                        thermostat->IsSimulatedDevice = false;
                        thermostat->Version = "1.0";
                        thermostat->DeviceProperties.HubEnabledState = true;
                        thermostat->DeviceProperties.DeviceID = (char*)deviceId;

                        commandsMetadata = STRING_new();
                        if (commandsMetadata == NULL)
                        {
                            (void)printf("Failed on creating string for commands metadata\r\n");
                        }
                        else
                        {
                            /* Serialize the commands metadata as a JSON string before sending */
                            if (SchemaSerializer_SerializeCommandMetadata(GET_MODEL_HANDLE(Contoso, Thermostat), commandsMetadata) != SCHEMA_SERIALIZER_OK)
                            {
                                (void)printf("Failed serializing commands metadata\r\n");
                            }
                            else
                            {
                                unsigned char* buffer;
                                size_t bufferSize;
                                thermostat->Commands = (char*)STRING_c_str(commandsMetadata);

                                /* Here is the actual send of the Device Info */
                                if (SERIALIZE(&buffer, &bufferSize, thermostat->ObjectType, thermostat->Version, thermostat->IsSimulatedDevice, thermostat->DeviceProperties, thermostat->Commands) != CODEFIRST_OK)
                                {
                                    (void)printf("Failed serializing\r\n");
                                }
                                else
                                {
                                    (void)printf("%.*s\r\n", bufferSize, buffer);
                                    sendMessage(iotHubClientHandle, buffer, bufferSize);
                                }

                            }

                            STRING_delete(commandsMetadata);
                        }

                        ReportSystemProperties();
                        ReportSupportedMethods();
                        ReportConfigProperties();

                        thermostat->Temperature = 0;
                        thermostat->Humidity = 0;
                        thermostat->Light = 0;
                        thermostat->Sound = 0;
                        thermostat->DeviceId = (char*)deviceId;

                        while (1)
                        {
                            printf("Sleep for %u second...\r\n", g_telemetryInterval);
                            ThreadAPI_Sleep(g_telemetryInterval * 1000);

                            if (strcmp(g_firmwareVersion, "2.0") < 0)
                            {
                                int temperature = rand() % 20 + 65;
                                int humidity = rand() % 40 + 10;

                                snprintf(
                                    msgBuffer,
                                    sizeof(msgBuffer),
                                    "{ \"DeviceId\": \"%s\", \"Temperature\": %d, \"Humidity\": %d, \"Light\": 0, \"Sound\": 0 }",
                                    deviceId,
                                    temperature,
                                    humidity);

                                printf("%s.\r\n", msgBuffer);
                                sendMessage(iotHubClientHandle, msgBuffer, strlen(msgBuffer));
                            }
                            else
                            {
                                memset(msgText, 0, sizeof(msgText));

                                if (NULL == (fpConfig = fopen("AzureMessageSend", "r")))
                                {
                                    printf("Open message file fail.\r\n");
                                }
                                else
                                {
                                    fgets(msgText, sizeof(msgText), fpConfig);
                                    fclose(fpConfig);
                                }

                                ptr = strstr(msgText, ">CLIENT_SEND");
                                if (ptr)
                                {
                                    printf("Get CLIENT SEND: command\r\n");

                                    memset(msgBuffer, 0, sizeof(msgBuffer));

                                    for (i = 0; i < 12; i++)*(ptr + i) = 0;

                                    snprintf(msgBuffer, sizeof(msgBuffer), "{\"DeviceId\":\"%s\",%s}", deviceId, msgText);

                                    printf("%s.\r\n", msgBuffer);
                                    sendMessage(iotHubClientHandle, msgBuffer, strlen(msgBuffer));

                                    if (NULL == (fpConfig = fopen("AzureMessageSend", "w")))
                                    {
                                        printf("Open message file fail.\r\n");
                                    }
                                    else
                                    {
                                        fwrite("SEND OK!", 1, 8, fpConfig);
                                        fclose(fpConfig);
                                    }
                                }
                            }
                        }
                    }

                    DESTROY_MODEL_INSTANCE(thermostat);
                }
                IoTHubClient_Destroy(iotHubClientHandle);
            }
            serializer_deinit();
        }
        platform_deinit();
    }
}

int main(void)
{
    srand(time(NULL));
    LoadConfig();
    remote_monitoring_run();
    return 0;
}