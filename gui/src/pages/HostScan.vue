<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';

const isScanning = ref(false);
const scanStatus = ref("READY");
const iHost = ref("");

const option = reactive({
  network_address: "",
  prefix_len: 24,
  target_hosts:[],
  scan_type: "network",
  async_flag: true,
  dsn_lookup_flag: true,
  os_detection_flag: true,
  save_flag: false,
});

const result = reactive({
  hosts: [],
  host_scan_time: "",
  lookup_time: "",
  total_scan_time: "",
});

const sleep = msec => new Promise(resolve => setTimeout(resolve, msec));

const clickAddHost = (event) => {
  option.target_hosts.push(iHost.value);
};

const clickRemoveHost = (portNo) => {
  console.log(portNo);
  const index = option.target_hosts.indexOf(portNo);
  option.target_hosts.splice(index, 1);
};

const runHostScan = async() => {
  isScanning.value = true;
  await sleep(2000);
  const opt = {
    network_address: option.network_address,
    prefix_len: option.prefix_len,
    target_hosts: option.target_hosts,
    scan_type: option.scan_type,
    async_flag: option.async_flag,
    dsn_lookup_flag: option.dsn_lookup_flag,
    os_detection_flag: option.os_detection_flag,
    save_flag: option.save_flag,
  };
  invoke('exec_hostscan', { "opt": opt }).then((scan_result) => {
    isScanning.value = false;
    scanStatus.value = "END";
    console.log(scan_result);
    result.hosts = scan_result.hosts;
    result.host_scan_time = scan_result.host_scan_time;
    result.lookup_time = scan_result.lookup_time;
    result.total_scan_time = scan_result.total_scan_time;
    console.log(result);
  });
};

const clickScan = (event) => {
  runHostScan();
};

onMounted(() => {
  invoke('test_command');

  invoke('test_command_arg', { invokeMessage: 'Hello!' });
  
  invoke('test_command_return').then((message) => console.log(message));
  
  invoke('test_command_result')
  .then((message) => console.log(message))
  .catch((error) => console.error(error));

  invoke('test_command_async').then(() => console.log('Completed!'));

});
</script>

<template>
  <div class="card bg-base-100 shadow-xl">
  <div class="card-body">
    <h2 class="card-title">Host Scan</h2>
    <!--Option Body-->
    <div class="grid grid-cols-4 gap-4">
    <div>
      <label class="label">
        <span class="label-text">Network Address</span>
      </label>
      <input type="text" v-model="option.network_address" placeholder="xxx.xxx.xxx.0" class="input input-bordered w-full max-w-md" />
    </div>
    <div>
      <label class="label">
        <span class="label-text">Prefix</span>
      </label>
      <input type="number" v-model="option.prefix_len" min="8" max="30" placeholder="24" class="input input-bordered w-full max-w-md" />
    </div>
    <div>
      <label class="label">
        <span class="label-text">Scan Type</span>
      </label>
      <select v-model="option.scan_type" class="select select-bordered w-full max-w-md">
        <option disabled selected value="">Select</option>
        <option value="network">Network</option>
        <option value="custom_list">Custom List</option>
      </select>
    </div>
    <div>
      <label class="label">
        <span class="label-text">Host List</span>
      </label>
      <!-- The button to open modal -->
      <label for="my-modal" class="btn">Open List</label>
      <!-- Put this part before </body> tag -->
      <input type="checkbox" id="my-modal" class="modal-toggle" />
      <div class="modal">
        <div class="modal-box">
          <h3 class="font-bold text-lg">Host List</h3>
          <div class="grid grid-cols-2 gap-4 mt-4">
            <div>
              <label class="input-group m-2">
                <input type="text" v-model="iHost" placeholder="Add Target Host …" class="input input-bordered input-sm" />
                <button @click="clickAddHost" class="btn btn-square btn-sm">Add</button>
              </label>
            </div>
          </div>
          
          <div class="overflow-y-auto max-h-48">
            <table class="table table-compact w-full">
            <thead>
              <tr>
                <th>IP Address</th> 
                <th>Operation</th> 
              </tr>
            </thead> 
            <tbody>
              <tr v-for="host in option.target_hosts" :key="host">
                <th>{{ host }}</th>
                <td><button v-bind:id="`remove-${host}`" @click="clickRemoveHost(host)" class="btn btn-outline btn-error btn-xs">Remove</button></td>
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
          <input type="checkbox" v-model="option.dsn_lookup_flag" checked="checked" class="checkbox" />
          <span class="label-text">DNS Lookup</span> 
        </label>
      </div>
    </div>
    <div>
      <div class="form-control">
        <label class="input-group">
          <input type="checkbox" v-model="option.os_detection_flag" checked="checked" class="checkbox" />
          <span class="label-text">OS Detection(TTL)</span> 
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
        Scan report
      </div>
      <div class="collapse-content"> 
        <div>
          <div class="stats shadow">
          <div class="stat">
            <div class="stat-title">Target</div>
            <div class="stat-value">Test</div>
            <div class="stat-desc">Test</div>
          </div>
        </div>
        <div class="stats shadow">
          <div class="stat">
            <div class="stat-title">Host Scan Time</div>
            <div class="stat-value">Test</div>
            <div class="stat-desc">Test</div>
          </div>
        </div>

        <div class="stats shadow">
          <div class="stat">
            <div class="stat-title">Lookup Time</div>
            <div class="stat-value">Test</div>
            <div class="stat-desc">Test</div>
          </div>
        </div>
        <div class="stats shadow">
          <div class="stat">
            <div class="stat-title">Total Scan Time</div>
            <div class="stat-value">Test</div>
            <div class="stat-desc">Test</div>
          </div>
        </div>
        </div>
        <div class="m-2">
          Hosts
          <table class="table w-full">
        <thead>
          <tr>
            <th>IP Address</th>
            <th>Host Name</th>
            <th>OS</th>
            <th>MAC Address</th>
            <th>Vendor Info</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="host in result.hosts" :key="host.ip_addr">
            <td>{{host.ip_addr}}</td>
            <td>{{host.host_name}}</td>
            <td>{{host.os_name}}</td>
            <td>{{host.mac_addr}}</td>
            <td>{{host.vendor_info}}</td>
          </tr>
        </tbody>
        </table>
        </div>
      </div>
    </div>
  </div>
</div>
  
</template>
