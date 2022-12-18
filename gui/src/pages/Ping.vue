<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { debounce } from 'lodash';

const isPinging = ref(false);
const pingStatus = ref("READY");
const innerHeight = ref(window.innerHeight);
const headerHeight = 500;
const contentHeight = ref(300);

const option = reactive({
  target_host: "",
  protocol: "ICMPv4",
  port: 0,
  count: 4,
  os_detection_flag: true,
  save_flag: false,
});

const runPing = async() => {
  isPinging.value = true;
  const opt = {
    target_host: option.target_host,
    protocol: option.protocol,
    port: option.port,
    count: option.count,
    os_detection_flag: option.os_detection_flag,
    save_flag: option.save_flag,
  };
  invoke('exec_ping', { "opt": opt }).then((ping_stat) => {
    isPinging.value = false;
    pingStatus.value = "END";
    console.log(ping_stat);
  });
};

const clickPing = (event) => {
  runPing();
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
  invoke('test_command_arg', { invokeMessage: 'Ping' });
  window.addEventListener('resize', debounce(checkWindowSize, 100));
});

onUnmounted(() => {
  window.removeEventListener('resize', checkWindowSize);
});
</script>

<template>
  <div class="card bg-base-100 shadow-xl">
  <div class="card-body">
    <h2 class="card-title">Ping</h2>
    <!--Option Body-->
    <div class="grid grid-cols-4 gap-4">
    <div>
      <label class="label">
        <span class="label-text">IP Address</span>
      </label>
      <input type="text" v-model="option.target_host" placeholder="IP Address or Host Name" class="input input-bordered w-full max-w-md" />
    </div>
    <div>
      <label class="label">
        <span class="label-text">Protocol</span>
      </label>
      <select v-model="option.protocol" class="select select-bordered w-full max-w-md">
        <option disabled selected value="">Select</option>
        <option value="ICMPv4">ICMP</option>
        <option value="TCP">TCP</option>
        <option value="UDP">UDP</option>
      </select>
    </div>
    <div>
      <label class="label">
        <span class="label-text">Port</span>
      </label>
      <input type="number" v-model="option.port" min="0" max="65535" placeholder="80" class="input input-bordered w-32 max-w-md" />
    </div>
    <div>
      <label class="label">
        <span class="label-text">Count</span>
      </label>
      <input type="number" v-model="option.count" min="1" max="64" placeholder="4" class="input input-bordered w-32 max-w-md" />
    </div>
  </div>
  <div class="grid grid-cols-4 gap-4 mt-4">
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
      <button class="btn btn-primary" @click="clickPing">
        <div v-if="isPinging">
          <div class="animate-spin h-5 w-5 border-4 rounded-full border-t-transparent"></div>
        </div>
        <div v-else>
        </div>
        Ping
      </button>

    </div>
  </div>
</div>

<div class="overflow-auto">

<div v-if="isPinging">
  <div class="flex justify-center mt-4">
    <div class="animate-spin h-10 w-10 border-4 rounded-full border-t-transparent"></div>
    <div class="text-xl font-medium">Pinging...</div>
  </div>
</div>
<div v-else-if="pingStatus === 'READY'">
  <div class="flex justify-center mt-4">
    <div class="text-xl font-medium">No Data</div>
  </div>
</div>
<div v-else>
  <div tabindex="0" class="collapse collapse-open"> 
    <div class="collapse-title text-xl font-medium">
      Ping report for {{ option.target_host }}
    </div>
    <div class="collapse-content"> 
      <el-scrollbar :max-height="contentHeight + 'px'">

      </el-scrollbar>
    </div>
  </div>
</div>
</div>

</template>
