(function(){
  try {
    if (location.protocol === 'http:' &&
        location.hostname !== 'localhost' &&
        location.hostname !== '127.0.0.1') {
      var target = 'https://' + location.host + location.pathname + location.search + location.hash;
      location.replace(target);
    }
  } catch(e){ /* no-op */ }
})();