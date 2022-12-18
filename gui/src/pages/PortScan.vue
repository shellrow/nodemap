<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { debounce } from 'lodash';

const isScanning = ref(false);
const scanStatus = ref("READY");
const iPort = ref(1);
const iMinPort = ref(1);
const iMaxPort = ref(1000);
const innerHeight = ref(window.innerHeight);
const headerHeight = 500;
const contentHeight = ref(300);

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

const clickAddPort = (event) => {
  option.ports.push(iPort.value);
};

const clickAddPortRange = (event) => {
  console.log(iMinPort.value);
  console.log(iMaxPort.value);
  for (let port = iMinPort.value; port <= iMaxPort.value; port++) {
    option.ports.push(port);
  }
};

const clickRemovePort = (portNo) => {
  console.log(portNo);
  const index = option.ports.indexOf(portNo);
  option.ports.splice(index, 1);
};

const runPortScan = async() => {
  isScanning.value = true;
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
    isScanning.value = false;
    scanStatus.value = "END";
    console.log(scan_result);
    result.ip_addr = scan_result.host.ip_addr;
    result.host_name = scan_result.host.host_name;
    result.mac_addr = scan_result.host.mac_addr;
    result.vendor_name = scan_result.host.vendor_info;
    result.os_name = scan_result.host.os_name;
    result.os_version = scan_result.host.os_name;
    result.cpe = scan_result.host.cpe;
    result.cpe_detail = scan_result.host.cpe;
    result.ports = scan_result.ports;
  });
};

const clickScan = (event) => {
  runPortScan();
};

const checkWindowSize = () => {
  innerHeight.value = window.innerHeight;
  if (innerHeight.value - headerHeight < 0) {
    contentHeight.value = 0;
  }else{
    contentHeight.value = innerHeight.value - headerHeight;
  }
};

onMounted(() => {
  invoke('test_command');

  invoke('test_command_arg', { invokeMessage: 'Hello!' });
  
  invoke('test_command_return').then((message) => console.log(message));
  
  invoke('test_command_result')
  .then((message) => console.log(message))
  .catch((error) => console.error(error));

  invoke('test_command_async').then(() => console.log('Completed!'));

  window.addEventListener('resize', debounce(checkWindowSize, 100));

});

onUnmounted(() => {
  window.removeEventListener('resize', checkWindowSize);
});

</script>

<template>
  <div class="card bg-base-100 shadow-xl">
  <div class="card-body">
    <h2 class="card-title">Port Scan</h2>
    <!--Option Body-->
    <div class="grid grid-cols-4 gap-4">
    <div>
      <label class="label">
        <span class="label-text">Host</span>
      </label>
      <input type="text" v-model="option.target_host" placeholder="IP Address or Host Name" class="input input-bordered w-full max-w-md" />
    </div>
    <div>
      <label class="label">
        <span class="label-text">Port</span>
      </label>
      <select v-model="option.port_option" class="select select-bordered w-full max-w-md">
        <option disabled selected value="">Select</option>
        <option value="default">Default(1005 ports)</option>
        <option value="well_known">Well Known(Top 1000)</option>
        <option value="custom_list">Custom List</option>
      </select>
    </div>
    <div>
      <label class="label">
        <span class="label-text">Port List</span>
      </label>
      <!-- The button to open modal -->
      <label for="my-modal" class="btn">Open List</label>
      <!-- Put this part before </body> tag -->
      <input type="checkbox" id="my-modal" class="modal-toggle" />
      <div class="modal">
        <div class="modal-box">
          <h3 class="font-bold text-lg">Port List</h3>
          <div class="grid grid-cols-2 gap-4 mt-4">
            <div>
              <label class="input-group m-2">
                <input type="number" min="1" max="65535" v-model="iPort" placeholder="Add Port …" class="input input-bordered input-sm" />
                <button @click="clickAddPort" class="btn btn-square btn-sm">Add</button>
              </label>
            </div>
            <div>
              <label class="input-group m-2">
                <input type="number" min="1" max="65535" v-model="iMinPort" class="input input-bordered input-sm" /> 
                <input type="number" min="1" max="65535" v-model="iMaxPort" class="input input-bordered input-sm" /> 
                <button @click="clickAddPortRange" class="btn btn-square btn-sm">Add</button>
              </label>
            </div>
          </div>
          
          <div class="overflow-y-auto max-h-48">
            <table class="table table-compact w-full">
            <thead>
              <tr>
                <th>Port No</th> 
                <th>Operation</th> 
              </tr>
            </thead> 
            <tbody>
              <tr v-for="port in option.ports" :key="port">
                <th>{{ port }}</th>
                <td><button v-bind:id="`remove-${port}`" @click="clickRemovePort(port)" class="btn btn-outline btn-error btn-xs">Remove</button></td>
              </tr>
            </tbody> 
          </table>
          </div>
          <div class="modal-action">
            <label for="my-modal" class="btn">Close</label>
          </div>
        </div>
      </div>
    </div>
    <div>
      <label class="label">
        <span class="label-text">Scan Type</span>
      </label>
      <select v-model="option.scan_type" class="select select-bordered w-full max-w-md">
        <option disabled selected value="">Select</option>
        <option value="tcp_syn_scan">TCP SYN Scan</option>
        <option value="tcp_connect_scan">TCP Connect Scan</option>
      </select>
    </div>
  </div>
  <div class="grid grid-cols-4 gap-4 mt-4">
    <div>
      <div class="form-control">
        <label class="input-group">
          <input type="checkbox" v-model="option.async_flag" checked="checked" class="checkbox" />
          <span class="label-text">Async</span> 
        </label>
      </div>
    </div>
    <div>
      <div class="form-control">
        <label class="input-group">
          <input type="checkbox" v-model="option.service_detection_flag" checked="checked" class="checkbox" />
          <span class="label-text">Service Detection</span> 
        </label>
      </div>
    </div>
    <div>
      <div class="form-control">
        <label class="input-group">
          <input type="checkbox" v-model="option.os_detection_flag" checked="checked" class="checkbox" />
          <span class="label-text">OS Detection</span> 
        </label>
      </div>
    </div>
    <div>
      <div class="form-control">
        <label class="input-group">
          <input type="checkbox" v-model="option.save_flag" checked="checked" class="checkbox" />
          <span class="label-text">Save</span> 
        </label>
      </div>
    </div>
  </div>
    <!--Option Body-->
    <div class="card-actions justify-end">
      <button class="btn btn-primary" @click="clickScan">
        <div v-if="isScanning">
          <div class="animate-spin h-5 w-5 border-4 rounded-full border-t-transparent"></div>
        </div>
        <div v-else>
        </div>
        Scan
      </button>
      
    </div>
  </div>
</div>

<div class="overflow-auto">

  <div v-if="isScanning">
    <div class="flex justify-center mt-4">
      <div class="animate-spin h-10 w-10 border-4 rounded-full border-t-transparent"></div>
      <div class="text-xl font-medium">Scanning...</div>
    </div>
  </div>
  <div v-else-if="scanStatus === 'READY'">
    <div class="flex justify-center mt-4">
      <div class="text-xl font-medium">No Data</div>
    </div>
  </div>
  <div v-else>
    <div tabindex="0" class="collapse collapse-open"> 
      <div class="collapse-title text-xl font-medium">
        Scan report for {{ result.ip_addr }}
      </div>
      <div class="collapse-content"> 
        <el-scrollbar :max-height="contentHeight + 'px'">
          <div>
          <div class="stats shadow">
          <div class="stat">
            <div class="stat-title">Host</div>
            <div class="stat-value">{{ result.ip_addr }}</div>
            <div class="stat-desc">{{ result.host_name }}</div>
          </div>
        </div>
        <div class="stats shadow">
          <div class="stat">
            <div class="stat-title">MAC Address</div>
            <div class="stat-value">{{ result.mac_addr }}</div>
            <div class="stat-desc">{{ result.vendor_name }}</div>
          </div>
        </div>

        <div class="stats shadow">
          <div class="stat">
            <div class="stat-title">OS Name</div>
            <div class="stat-value">{{ result.os_name }}</div>
            <div class="stat-desc">{{ result.os_version }}</div>
          </div>
        </div>
        <div class="stats shadow">
          <div class="stat">
            <div class="stat-title">CPE</div>
            <div class="stat-value">{{ result.cpe }}</div>
            <div class="stat-desc">{{ result.cpe_detail }}</div>
          </div>
        </div>
        </div>
        <div class="m-2">
          Port Info
          <table class="table w-full">
        <thead>
          <tr>
            <th>Port No</th>
            <th>Status</th>
            <th>Service Name</th>
            <th>Service Version</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="port in result.ports" :key="port.port_number">
            <td>{{port.port_number}}</td>
            <td>{{port.port_status}}</td>
            <td>{{port.service_name}}</td>
            <td>{{port.service_version}}</td>
          </tr>
        </tbody>
        </table>
        </div>
        </el-scrollbar>
      </div>
    </div>
  </div>
</div>
  
</template>
