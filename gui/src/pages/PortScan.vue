<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { debounce } from 'lodash';
import {sleep} from '../logic/shared.js';

const scanning = ref(false);

const option = reactive({
    target_host: "",
    port_option: "default",
    ports:[],
    scan_type: "tcp_syn_scan",
    async_flag: true,
    service_detection_flag: true,
    os_detection_flag: true,
    save_flag: false,
});

const result = reactive({
    ip_addr: "",
    host_name: "",
    ports: [],
    mac_addr: "",
    vendor_name: "",
    os_name: "",
    os_version: "",
    cpe: "",
    cpe_detail: "",
});

const port_options = [
  {
    value: 'default',
    label: 'Default(1005 ports)',
  },
  {
    value: 'well_known',
    label: 'Well Known(Top 1000)',
  },
  {
    value: 'custom_list',
    label: 'Custom List',
  },
];

const scan_type_options = [
  {
    value: 'tcp_syn_scan',
    label: 'TCP SYN Scan',
  },
  {
    value: 'tcp_connect_scan',
    label: 'TCP Connect Scan',
  },
];

const runPortScan = async() => {
  scanning.value = true;
  const opt = {
    target_host: option.target_host,
    port_option: option.port_option,
    ports: option.ports,
    scan_type: option.scan_type,
    async_flag: option.async_flag,
    service_detection_flag: option.service_detection_flag,
    os_detection_flag: option.os_detection_flag,
    save_flag: option.save_flag,
  };
  invoke('exec_portscan', { "opt": opt }).then((scan_result) => {
    scanning.value = false;
    let open_ports = [];
    scan_result.ports.forEach(port => {
      if (port.port_status === "Open"){
        open_ports.push(port);
      }
    });
    console.log(scan_result);
    result.ip_addr = scan_result.host.ip_addr;
    result.host_name = scan_result.host.host_name;
    result.mac_addr = scan_result.host.mac_addr;
    result.vendor_name = scan_result.host.vendor_info;
    result.os_name = scan_result.host.os_name;
    result.os_version = scan_result.host.os_name;
    result.cpe = scan_result.host.cpe;
    result.cpe_detail = scan_result.host.cpe;
    result.ports = open_ports;
  });
};

const clickScan = (event) => {
  runPortScan();
};

onMounted(() => {
    invoke('test_command_arg', { invokeMessage: 'PortScan' });
    invoke('test_command_return').then((message) => console.log(message));
});

onUnmounted(() => {

});

</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.item {
  margin-bottom: 18px;
}

</style>

<template>
    <el-card class="box-card">
        <!-- Header -->
        <template #header>
            <div class="card-header">
                <span>Port Scan</span>
                <el-button type="primary" plain @click="clickScan" :loading="scanning" >Scan</el-button>
            </div>
        </template>
        <!-- Header -->
        <!-- Options -->
        <el-row :gutter="20">
            <el-col :span="6">
                <p style="font-size: var(--el-font-size-small)">Target</p>
                <el-input v-model="option.target_host" placeholder="Address or Name" />
            </el-col>
            <el-col :span="6">
                <p style="font-size: var(--el-font-size-small)">Port</p>
                <el-select v-model="option.port_option" placeholder="Select">
                    <el-option v-for="item in port_options"
                        :key="item.value"
                        :label="item.label"
                        :value="item.value"
                    />
                </el-select>
            </el-col>
            <el-col :span="6">
                <p style="font-size: var(--el-font-size-small)">Port List</p>
                <el-button type="info" plain>List</el-button>
            </el-col>
            <el-col :span="6">
                <p style="font-size: var(--el-font-size-small)">Scan Type</p>
                <el-select v-model="option.scan_type" placeholder="Select">
                    <el-option v-for="item in scan_type_options"
                        :key="item.value"
                        :label="item.label"
                        :value="item.value"
                    />
                </el-select>
            </el-col>
        </el-row>
        <el-row :gutter="20">
            <el-col :span="6">
                <el-checkbox v-model="option.async_flag" label="Async" />
            </el-col>
            <el-col :span="6">
                <el-checkbox v-model="option.service_detection_flag" label="Service Detection" />
            </el-col>
            <el-col :span="6">
                <el-checkbox v-model="option.os_detection_flag" label="OS Detection" />
            </el-col>
            <el-col :span="6">
                <el-checkbox v-model="option.save_flag" label="Save" />
            </el-col>
        </el-row>
        <!-- Options -->
    </el-card>
    <!-- Results -->
    <div v-loading="scanning" element-loading-text="Scanning..." class="mt-2">
      <el-descriptions
        title="Scan Result"
        direction="vertical"
        :column="4"
        border
      >
        <el-descriptions-item label="IP Address">{{ result.ip_addr }}</el-descriptions-item>
        <el-descriptions-item label="Host Name">{{ result.host_name }}</el-descriptions-item>
        <el-descriptions-item label="MAC Address" :span="2">{{ result.mac_addr }}</el-descriptions-item>
        <el-descriptions-item label="OS Name">{{ result.os_name }}</el-descriptions-item>
        <el-descriptions-item label="CPE">{{ result.cpe }}</el-descriptions-item>
      </el-descriptions>

      <el-table :data="result.ports" style="width: 100%" class="mt-2">
        <el-table-column prop="port_number" label="Port No" />
        <el-table-column prop="port_status" label="Status"  />
        <el-table-column prop="service_name" label="Service Name" />
        <el-table-column prop="service_version" label="Service Version" />
      </el-table>
    </div>
    <!-- Results -->
</template>
