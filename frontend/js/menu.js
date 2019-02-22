// internet.nl - menu.js

// Vars
var header      = document.querySelector('header .wrap'),
    menu        = document.querySelector('#sitenav'),
    langswitch  = document.querySelector('#language-switch-header-container'),
    menuButton  = document.querySelector('.menu-button');

function hideMenuButton(document, window, undefined) {

  header.classList.remove('menu-with-js-actions');

  header.classList.add('no-menu-button');

  menu.setAttribute('aria-hidden', 'false');
  langswitch.setAttribute('aria-hidden', 'false');

  var ele = document.getElementById("menu-button");

  if (ele) {
    // Remove button from page
    header.removeChild(menuButton);
  }

}

function showMenuButton(document, window, undefined) {

  'use strict';

  header.classList.add('menu-with-js-actions');
  header.classList.remove('no-menu-button');

  menuButton = document.createElement('button');


  // Button properties
  menuButton.classList.add('menu-button');
  menuButton.setAttribute('id', 'menu-button');
  menuButton.setAttribute('aria-label', 'Menu');
  menuButton.setAttribute('aria-expanded', 'false');
  menuButton.setAttribute('aria-controls', 'sitenav');
  menuButton.innerHTML = '<i>&#x2261;</i><b>&nbsp;menu</b>';

  // Menu properties
  menu.setAttribute('aria-hidden', 'true');
  menu.setAttribute('aria-labelledby', 'menu-button');

  langswitch.setAttribute('aria-hidden', 'true');

  // Add button to page
  header.insertBefore(menuButton, langswitch);

  // Handle button click event
  menuButton.addEventListener('click', function () {

    // If active...
    if (menu.classList.contains('active')) {
      // Hide

      header.classList.remove('active');

      menu.classList.remove('active');
      menu.setAttribute('aria-hidden', 'true');

      langswitch.classList.remove('active');
      langswitch.setAttribute('aria-hidden', 'true');

      menuButton.setAttribute('aria-expanded', 'false');
    } else {
      // Show

      header.classList.add('active');

      menu.classList.add('active');
      menu.setAttribute('aria-hidden', 'false');

      langswitch.classList.add('active');
      langswitch.setAttribute('aria-hidden', 'false');

      menuButton.setAttribute('aria-expanded', 'true');
    }
  }, false);
}

// =========================================================================================================

// media query change
function WidthChange(mq) {

    if (mq.matches) {
        // window width is at least 1000px
        // don't show menu button
        hideMenuButton(document, window);
    }
    else {
        // window width is less than 500px
        // DO show menu button
        showMenuButton(document, window);

    }

}

// =========================================================================================================

// media query event handler
if (matchMedia) {
    var mq = window.matchMedia('(min-width: 740px)');
    mq.addListener(WidthChange);
    WidthChange(mq);
}


// =========================================================================================================
