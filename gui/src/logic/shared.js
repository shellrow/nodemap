export const sleep = msec => new Promise(resolve => setTimeout(resolve, msec));

export function isValidIPaddress(ipaddress) 
{
    if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ipaddress))
    {
        return true;
    }
    return false;
}

export function isValidHostname(value) {
    if (typeof value !== 'string'){
        return false;
    } 

    const validHostnameChars = /^[a-zA-Z0-9-.]{1,253}\.?$/g
    if (!validHostnameChars.test(value)) {
      return false
    }
  
    if (value.endsWith('.')) {
      value = value.slice(0, value.length - 1)
    }
  
    if (value.length > 253) {
      return false
    }
  
    const labels = value.split('.')
  
    const isValid = labels.every(function (label) {
      const validLabelChars = /^([a-zA-Z0-9-]+)$/g
  
      const validLabel = (
        validLabelChars.test(label) &&
        label.length < 64 &&
        !label.startsWith('-') &&
        !label.endsWith('-')
      )
      return validLabel
    }) 
    return isValid
}
