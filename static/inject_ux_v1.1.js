(function(){
  'use strict';
  function getToastEl(){
    var el = document.getElementById('inject-toast');
    if (!el){
      el = document.createElement('div');
      el.id = 'inject-toast';
      document.body.appendChild(el);
    }
    return el;
  }

  function showToast(msg, type, ttl){
    try{
      var el = getToastEl();
      el.className = (type||'info') + ' show';
      el.textContent = msg || '';
      el.style.display = 'block';
      if (!ttl) ttl = 3000;
      clearTimeout(el._hideTO);
      el._hideTO = setTimeout(function(){
        el.classList.remove('show');
        el.classList.add('hide');
        setTimeout(function(){ el.style.display = 'none'; el.classList.remove('hide'); }, 250);
      }, ttl);
    } catch(e){ console.warn('inject_ux toast failed', e); }
  }

  window.vspInjectUX = window.vspInjectUX || {};
  window.vspInjectUX.showToast = showToast;

  // Provide a global `toast()` fallback used in some panels
  if (typeof window.toast !== 'function'){
    window.toast = function(msg, type){ showToast(msg, type); };
  }

})();
