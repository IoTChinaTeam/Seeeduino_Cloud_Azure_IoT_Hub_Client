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


static char hostName[128] = {0, };
static char deviceId[128] = {0, };
static char deviceKey[128] = {0, };
static char hubSuffix[128] = {0, };

static char msgText[2048] = {0, };
static char msgBuffer[2048] = {0, };

static int telemetryInterval = 5;


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


static void ReceivedMessageSave(char *buffer)
{
    FILE *fpConfig;
    
    if (NULL == (fpConfig=fopen("AzureMessageReceive","w")))
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
    char data[128] = {0, };
    snprintf(data, sizeof(data), "\"SetTemperature\":%d", temperature);
    (void)printf("%s\r\n", data);
    ReceivedMessageSave(data);
    return EXECUTE_COMMAND_SUCCESS;
}

EXECUTE_COMMAND_RESULT SetHumidity(Thermostat* thermostat, int humidity)
{
    char data[128] = {0, };
    snprintf(data, sizeof(data), "\"SetHumidity\":%d", humidity);
    (void)printf("%s\r\n", data);
    ReceivedMessageSave(data);
    return EXECUTE_COMMAND_SUCCESS;
}

EXECUTE_COMMAND_RESULT SetLight(Thermostat* thermostat, int light)
{
    char data[128] = {0, };
    snprintf(data, sizeof(data), "\"SetLight\":%d", light);
    (void)printf("%s\r\n", data);
    ReceivedMessageSave(data);
    return EXECUTE_COMMAND_SUCCESS;
}

EXECUTE_COMMAND_RESULT SetSound(Thermostat* thermostat, int sound)
{
    char data[128] = {0, };
    snprintf(data, sizeof(data), "\"SetSound\":%d", sound);
    (void)printf("%s\r\n", data);
    ReceivedMessageSave(data);
    return EXECUTE_COMMAND_SUCCESS;
}

EXECUTE_COMMAND_RESULT SetRGBLed(Thermostat* thermostat, int rgbled)
{
    char data[128] = {0, };
    snprintf(data, sizeof(data), "\"SetRGBLed\":%d", rgbled);
    (void)printf("%s\r\n", data);
    ReceivedMessageSave(data);
    return EXECUTE_COMMAND_SUCCESS;
}

static void SendConfirmationCallback(IOTHUB_CLIENT_CONFIRMATION_RESULT result, void* userContextCallback)
{   
    FILE *fpConfig;
    char data[128] = {0, };
    
    snprintf(data, sizeof(data), "%s", ENUM_TO_STRING(IOTHUB_CLIENT_CONFIRMATION_RESULT, result));
    (void)printf(data);
    
    if (NULL == (fpConfig=fopen("run.log","w")))
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
        if (NULL == (fpConfig=fopen("AzureMessageReceive","w")))
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
    if(ptr)
    {
        result = 0;
        return result;  
    }
    
    ptr = strstr(buffer, "HOST_NAME:");
    if(ptr)
    {
        i = 0;
        while(1)
        {
            if(i < sizeof(hostName))hostName[i ++] = *(ptr + 10 + i);
            if(*(ptr + 10 + i) == '.' && *(ptr + 10 + i + 1) == 'a' && *(ptr + 10 + i + 2) == 'z' && *(ptr + 10 + i + 3) == 'u' && *(ptr + 10 + i + 4) == 'r' && *(ptr + 10 + i + 5) == 'e')break;
        }
        hostName[i] = '\0';
        printf("hostName is %s\r\n", hostName);
    }
    
    ptr = strstr(buffer, "azure-devices.");
    if(ptr)
    {
        i = 0;
        while(1)
        {
            if(i < sizeof(hubSuffix))hubSuffix[i ++] = *(ptr + i);
            if(*(ptr + i) == '\n')break;
        }
        hubSuffix[i] = '\0';
        printf("hubSuffix is %s\r\n", hubSuffix);
    }
    
    ptr = strstr(buffer, "DEVICE_ID:");
    if(ptr)
    {
        i = 0;
        while(1)
        {
            if(i < sizeof(deviceId))deviceId[i ++] = *(ptr + 10 + i);
            if(*(ptr + 10 + i) == '\n')break;
        }
        deviceId[i] = '\0';
        printf("deviceId is %s\r\n", deviceId);
    }
    
    ptr = strstr(buffer, "DEVICE_KEY:");
    if(ptr)
    {
        i = 0;
        while(1)
        {
            if(i < sizeof(deviceKey))deviceKey[i ++] = *(ptr + 11 + i);
            if(*(ptr + 11 + i) == 0 || *(ptr + 11 + i) == '\n')break;
        }
        deviceKey[i] = '\0';
        printf("deviceKey is %s\r\n", deviceKey);
    }
    
    return result;
}

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

void ReportSystemProperties(IOTHUB_CLIENT_HANDLE iotHubClientHandle)
{
    struct sysinfo sysInfo;
    sysinfo(&sysInfo);
        
    struct utsname sysName;
    uname(&sysName);
    
    unsigned char report[256] = { 0 };
    
    size_t len = snprintf(report, sizeof(report), "{ 'System': { 'InstalledRAM': '%u MB', 'Platform': '%s %s' } }",
        sysInfo.totalram * sysInfo.mem_unit / 1024 / 1024,
        sysName.sysname,
        sysName.release);
    if (IoTHubClient_SendReportedState(iotHubClientHandle, report, len, NULL, NULL) != IOTHUB_CLIENT_OK)
    {	
        (void)printf("Failed to report system properties\r\n");
    }
    else
    {
        (void)printf("System properties successfully reported\r\n");
    }
}

void ReportSupportedMethods(IOTHUB_CLIENT_HANDLE iotHubClientHandle)
{
    unsigned char report[256] = { 0 };
    
    size_t len = snprintf(report, sizeof(report), "{ 'SupportedMethods': { 'SetRGBLED--rgb-int': 'Set color of LED' } }");
    if (IoTHubClient_SendReportedState(iotHubClientHandle, report, len, NULL, NULL) != IOTHUB_CLIENT_OK)
    {
        (void)printf("Failed to report supported methods\r\n");
    }
    else
    {
        (void)printf("Supported methods successfully reported\r\n");
    }
}

void ReportConfigProperties(IOTHUB_CLIENT_HANDLE iotHubClientHandle)
{
    unsigned char report[256] = { 0 };
    
    size_t len = snprintf(report, sizeof(report), "{ 'Config': { 'TelemetryInterval': %d } }", telemetryInterval);
    if (IoTHubClient_SendReportedState(iotHubClientHandle, report, len, NULL, NULL) != IOTHUB_CLIENT_OK)
    {	
        (void)printf("Failed to report config properties\r\n");
    }
    else
    {
        (void)printf("Config properties successfully reported\r\n");
    }
}

bool GetNumberFromString(const unsigned char* text, size_t size, int* pValue)
{
    const unsigned char* pStart = text;	
    for( ; pStart < text + size; pStart++)
    {
        if (isdigit(*pStart))
        {
            break;
        }
    }
    
    const unsigned char* pEnd = pStart + 1;
    for ( ; pEnd <= text + size; pEnd++)
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

int OnDeviceMethodInvoked(const char* method_name, const unsigned char* payload, size_t size, unsigned char** response, size_t* resp_size, void* userContextCallback)
{
    printf("Method call: name = %s, payload = %s\r\n", method_name, payload);
    
    if (strcmp(method_name, "SetRGBLED") != 0)
    {
        AllocAndPrintf(response, resp_size, "{'message': 'Unknown method %s'}", method_name);
        return IOTHUB_CLIENT_OK;
    }
    
    int rgb;
    if (!GetNumberFromString(payload, size, &rgb))
    {
        AllocAndPrintf(response, resp_size, "{ 'message': 'Invalid payload' }");
    }
    else
    {
        FILE *fpConfig;
        if (NULL == (fpConfig=fopen("AzureMessageReceive","w")))		
        {
            printf("Open azure message content file fail.\r\n");

            AllocAndPrintf(response, resp_size, "{ 'message': 'Open azure message content file fail' }");
        }
        else
        {
            fprintf(fpConfig, "\"SetRGBLed\":%d", rgb);
            fclose(fpConfig);
            
            AllocAndPrintf(response, resp_size, "{ 'message': 'Accepted, rgb = %d' }", rgb);
        }
    }

    return IOTHUB_CLIENT_OK;
}

void OnDesiredPropertyChanged(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payLoad, size_t size, void* userContextCallback)
{
    printf("Property changed: %s", payLoad);
    
    unsigned char *p = strstr(payLoad, "\"TelemetryInterval\":");
    
    int interval;
    if (GetNumberFromString(p, size - (p - payLoad), &interval))
    {
        telemetryInterval = interval;
        
        IOTHUB_CLIENT_HANDLE iotHubClientHandle = (IOTHUB_CLIENT_HANDLE)userContextCallback;
        ReportConfigProperties(iotHubClientHandle);
    }
}

void remote_monitoring_run(void)
{
    FILE *fpConfig;
    char *ptr;
    char i;

    while(1)
    {
        if (NULL == (fpConfig=fopen("AzureConnectionString","r")))
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
                
                if(getAccountInfo(msgText))
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
                    else if (IoTHubClient_SetDeviceMethodCallback(iotHubClientHandle, OnDeviceMethodInvoked, (void*)iotHubClientHandle) != IOTHUB_CLIENT_OK)
                    {
                        printf("unable to IoTHubClient_SetDeviceMethodCallback\r\n");
                    }
                    else if (IoTHubClient_SetDeviceTwinCallback(iotHubClientHandle, OnDesiredPropertyChanged, (void*)iotHubClientHandle) != IOTHUB_CLIENT_OK)
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
                                    (void)printf("%s\r\n", buffer);
                                    sendMessage(iotHubClientHandle, buffer, bufferSize);
                                }

                            }

                            STRING_delete(commandsMetadata);
                        }
                        
                        ReportSystemProperties(iotHubClientHandle);
                        ReportSupportedMethods(iotHubClientHandle);
                        ReportConfigProperties(iotHubClientHandle);

                        thermostat->Temperature = 0;
                        thermostat->Humidity = 0;
                        thermostat->Light = 0;
                        thermostat->Sound = 0;
                        thermostat->DeviceId = (char*)deviceId;

                        while(1)
                        {
                            ThreadAPI_Sleep(telemetryInterval * 1000);
                            
                            memset(msgText, 0, sizeof(msgText));
                            
                            if (NULL == (fpConfig=fopen("AzureMessageSend","r")))
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
                                
                                for(i = 0;i < 12;i ++)*(ptr + i) = 0;
                                
                                snprintf(msgBuffer, sizeof(msgBuffer), "{\"DeviceId\":\"%s\",%s}", deviceId, msgText);
                                
                                printf("%s.\r\n", msgBuffer);
                                
                                sendMessage(iotHubClientHandle, msgBuffer, strlen(msgBuffer));
 
                                (void)printf("Wait for message send...\r\n");
                                
                                if (NULL == (fpConfig=fopen("AzureMessageSend","w")))
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
    remote_monitoring_run();
    return 0;
}

