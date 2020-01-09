/* $Id */
/*if (typeof afcads_params_for_dz == 'undefined' || typeof afcads_params_for_dz != 'object') {
	var afcads_params_for_dz = {};
}*/

var BROWSER_DETECTOR = {
	'ie' : (navigator.userAgent.indexOf('MSIE') >= 0) && (navigator.userAgent.indexOf('Opera') < 0)
};

function logger(msg) {
	if (typeof console == 'object') {
		console.log(msg);
	} else {}
}

var rela_jason;
var rel_resource_url = 'http://cache.soso.com/30d/img/discuz';
var rel_view_thread_url = 'forum.php?mod=viewthread&';
var ti = rel_title;

if (typeof source_type != 'undefined' && source_type =='discuz') {
	rel_view_thread_url = 'viewthread.php?';
}

if (typeof(charset) == 'undefined' || !charset) {
	var charset = 'gbk';
}

var rel_prepos = getParam('pre_pos');
var ext = getParam('ext');

my_siteid = parseInt(my_siteid);

var hint_num = 10;
var post_num = 10;
var rel_script_src = 'http://rel.discuz.soso.com/hu?version=14&site_id=' + my_siteid + '&thread_id=' + rel_tid + '&user_id=' + rel_uid + '&num=' + post_num + '&ti=' + rel_title + '&hint_num=' + hint_num + '&cs=' + charset;

if(rel_reltid) {
	rel_script_src += '&pre_thread_id=' + rel_reltid;
}

if(rel_prepos && rel_prepos != 'undefined') {
	rel_script_src += '&pre_pos=' + rel_prepos;
}

if(ext && ext != 'undefined') {
	rel_script_src += '&ext=' + ext;
}

if (typeof(rel_thread) == 'undefined' || !rel_thread) {
	rel_thread = '&#30456;&#20851;&#24086;&#23376;';
}

if (typeof(rel_recommend) == 'undefined' || !rel_recommend) {
	rel_recommend = '&#30456;&#20851;&#25512;&#33616;';
}

if (typeof discuz_uid !=  'undefined' && parseInt(discuz_uid)){
	rel_script_src += '&session_id=' + discuz_uid;
} else {
	if (typeof cookiepre != 'undefined' && (cookieval = getCookie(cookiepre + 'sid'))) {
		rel_script_src += '&session_id=' + cookieval;
	}
}

if (document.referrer){
	rel_script_src += '&refer=' + encodeURIComponent(document.referrer);
}

if (typeof(rel_views) != 'undefined') {
	rel_script_src += '&rel_views=' + rel_views;
}

if (typeof(rel_replies) != 'undefined') {
	rel_script_src +='&rel_replies=' + rel_replies;
}

request();

function request() {
	
	if (!document.getElementById('relate_subject')) {
		return false;    
	}
	
	if (!my_siteid) {
		return false;
	}
	try {
		var docHead = document.getElementsByTagName('head')[0];
		var script = document.createElement('script');
		script.setAttribute('type', 'text/javascript');
		script.setAttribute('src', rel_script_src);
		docHead.appendChild(script);
		if (BROWSER_DETECTOR.ie) {
			script.onreadystatechange = function() {
				if (this.readyState == 'loaded' || this.readyState == 'complete') {
					script.onreadstatechange = null;
					ShowRelateSubject();
				}
			}
		} else {
			script.onload  = function() {
				ShowRelateSubject();
			}
		}
	}
	catch (e) {}
}

function getCookie(name) {
	var cookies = document.cookie;
	var cookie;
	cookies = cookies.split(';');

	if(cookies.length) {
		for(var i=0; i<cookies.length; i++) {
			cookie = cookies[i].split('=');
			if(cookie[0].indexOf(name) != -1) {
				return cookie[1];
			}
		}
	}
	return false;
}

function getParam(name) {
	var url=window.location.href;
	params = url.split("?")[1];
	if (params) {
		items = params.split('&');
		for (i=0; i <= items.length; i++) {
			if (items[i]) {
				param = items[i].split('=');
				if (param[0] == name) {
					return param[1];
				}
			}
		}
	}
	return '';
}

function loadCSS(href) {
	var docHead = document.getElementsByTagName('head')[0];
	var style = document.createElement('link');
	style.setAttribute('type', 'text/css');
	style.setAttribute('rel', 'stylesheet');
	style.setAttribute('href', href);
	docHead.appendChild(style);
	return style;
}

function loadScript(src) {
	var docHead = document.getElementsByTagName('head')[0];
	var script = document.createElement('script');
	script.setAttribute('type', 'text/javascript');
	script.setAttribute('src', src);
	docHead.appendChild(script);
	return script;
}

/*function showAdv(advInfo) {
	var advUrl = 'http://cache.soso.com/afc/js/showads_if_discuz_titleads_specified.js?v20120529';

	afcads_params_for_dz.advLeftKey = {
		'afc_placementid' : advInfo.pLeft,
		'afc_width' : 200,
		'afc_height' : 25
	};
	
	afcads_params_for_dz.advRightKey = {
		'afc_placementid' : advInfo.pRight,
		'afc_width' : 200,
		'afc_height' : 25
	};
	loadScript(advUrl);
}*/

function isFromSearchEngine() {
	var referrer = document.referrer;

	if (referrer) {
		var reSearchEngine = /baidu|google|yahoo|ask|soso|sogou|gougou|youdao|bing/i;
		var urlParts = referrer.replace('http://', '').split('/');
		var host = urlParts.shift();

		return reSearchEngine.test(host) ? true : false;
	} else {
		return false;
	}
}

function ShowRelateSubject() {
	var rel_subject_obj = $('relate_subject');
	var css_href = 'http://discuz.gtimg.cn/search/styles/relate_subject.css';

	if (rel_subject_obj && rela_jason) {
		if ((typeof rela_jason.searchstatus != 'undefined') && (parseInt(rela_jason.searchstatus) == 0 || isNaN(parseInt(rela_jason.searchstatus)))) {
			return false;
		}

		loadCSS(css_href);

		var rel_items;
		var word_related = rela_jason;
		var fpCount = (rela_jason.forumposts && rela_jason.forumposts.length) ? rela_jason.forumposts.length : 0;
		var kwCount = (rela_jason.keywords && rela_jason.keywords.length) ? rela_jason.keywords.length : 0;
		//var adCount = (rela_jason.aditems && rela_jason.aditems.length) ? rela_jason.aditems.length : 0;
		//var maxAdCount = 2;
		var pre_pos;
		var searchUrl = 'search.php?mod=my&searchsubmit=true';
		var rel_li_items = '';
		var rel_kws = '';
		var margin_btm = 0;
		var rel_title = rel_recommend;
		var keyword = '';
		var rel_word_href = '';
		var rel_ext = '';
		var rno = 0;
		var rel_first_word = '';
		var rel_more = '';

		/*if (typeof rela_jason.adinfo != 'undefined' && rela_jason.adinfo.length) {
			advInfo = rela_jason.adinfo[0];
		}*/
		
		/*if (typeof is_5d6d_site != 'undefined' && is_5d6d_site === true) {
			var advInfo = {
				'pLeft': 115066,
				'pRight': 115067,
				'isShow': 1
			};
		}*/
		
		var rel_items = '<div class="rs_main"><div class="rs_head"><h3 ';
		/*var is_show_adv = (advInfo && advInfo.pLeft && advInfo.pRight) && (advInfo.isShow || (advInfo.onlySrch && isFromSearchEngine()));*/

		//var max_items = is_show_adv ? 7 : 9;
		var max_items = 9;

		//if (!is_show_adv) {
		rel_items += ' class="has_adv"';
		//}
		
		rel_items += '>(title)</h3></div>(#ul)(#more)(#p)</div>';

		if (kwCount) {
			if(typeof(searchDomain) == 'undefined' && typeof(srchotquery) == 'undefined') {
				var scbar_form = document.getElementById('scbar_form');
				var queries = new Array();
				if(scbar_form) {
					if(scbar_form.elements['sId'] && scbar_form.elements['cuId'] && scbar_form.elements['cuName'] && scbar_form.elements['gId'] && scbar_form.elements['agId'] && scbar_form.elements['egIds'] && scbar_form.elements['sign'] && scbar_form.elements['charset'] && scbar_form.elements['ts'] && scbar_form.elements['formhash']) {
						searchDomain = scbar_form.action;
						for(var i=0; i<scbar_form.elements.length; i++) {
							if(scbar_form.elements[i].name != 'srchtxt' && scbar_form.elements[i].name != 'searchsubmit' && scbar_form.elements[i].name != 'q' && scbar_form.elements[i].name != 'fId' && scbar_form.elements[i].name != 'source' && scbar_form.elements[i].name != 'srhlocality') {
									queries[i] = scbar_form.elements[i].name + '=' + scbar_form.elements[i].value;
							}
						}
						if(scbar_form.length) {
							srchotquery = queries.join('&');
						}
					}
				}
			}
			
			rel_first_word = encodeURIComponent(rela_jason['keywords'][0].word);

			if (typeof(searchDomain) != 'undefined' && typeof(srchotquery) != 'undefined' && searchDomain && srchotquery) {
				rel_more_href = searchDomain + '?q=' + rel_first_word + '&source=word.relrecmore' +  '&' + srchotquery;
			} else {
				rel_more_href = searchUrl + '&q=' + rel_first_word + '&source=word.relrecmore.';
			}

			if (fpCount && kwCount) {
				rel_more = '<div class="show_more"><a href="' + rel_more_href + '" target="_blank">&#26597;&#30475;&#26356;&#22810;>></a></div>';
			}
			
			if (kwCount > 1) {
				rel_kws += '<p class="kws_wrapper">';

				for(var j=0; j<kwCount; j++) {	
					
					if (j > hint_num-1) {
						break;
					}

					if(!rela_jason['keywords'][j].word) {
						continue;
					}

					keyword = rela_jason['keywords'][j].word;
					hintExtern = rela_jason['keywords'][j].src;
					encode_keyword = encodeURIComponent(keyword);

					if (typeof(searchDomain) != 'undefined' && typeof(srchotquery) != 'undefined' && searchDomain && srchotquery) {
						rel_word_href = searchDomain + '?q=' + encode_keyword + '&source=word.relrec.' + (j+1) + '&hintExtern=' + hintExtern + '&' + srchotquery;
					} else {
						rel_word_href = searchUrl + '&q=' + encode_keyword + '&source=word.relrec.' + (j+1) + '&hintExtern=' + hintExtern;
					}
					
					rel_kws += "<a onmouseout=\"this.style.textDecoration='none'\" onmouseover=\"this.style.textDecoration='underline'\" title=\"" + keyword +"\" href=\"" + rel_word_href + "\" target=\"_blank\">" + keyword + "</a>";
				}
				rel_kws += '</p>';
			}
		}

		if (fpCount){
			var search = [/\$\$HL_S\$\$/g, /\$\$HL_E\$\$/g];
			margin_btm = 5;
			rel_title = rel_thread;
			//adCount = adCount > maxAdCount ? maxAdCount : adCount;
			
			rel_li_items += '<ul id="rel_list">';

			/*if (is_show_adv) {
				rel_li_items += '<li id="advLeftKey" class="right_adv"></li><li id="advRightKey" class="left_adv"></li>';
			}*/

			for(var i=0; i<fpCount; i++) {
				pre_pos = rno + 1;
				rel_ext = word_related.forumposts[i].ext ? word_related.forumposts[i].ext : '';
				style_class = rno%2 ? 'left_item' : 'right_item';
				rel_li_items += '<li class="' + style_class + '"><a href="' + rel_view_thread_url + 'tid=' + word_related.forumposts[i].threadid + '&reltid=' + rel_tid +  (rel_reltid ? ('&pre_thread_id=' + rel_reltid) : '') + '&pre_pos=' + pre_pos + '&ext=' + rel_ext + '" target="_blank" title="' + word_related.forumposts[i].ti + '" onmouseover="this.style.textDecoration=\'underline\'" onmouseout="this.style.textDecoration=\'none\'">'+ word_related.forumposts[i].ti + '</a></li>';
				if(rno >= max_items) {
					break;
				}
				rno++;
			}
			rel_li_items += '</ul>';
		}

		if (fpCount || kwCount > 1) {
			rel_items = rel_items.replace('(#ul)', rel_li_items);
			rel_items = rel_items.replace('(#p)', rel_kws);
			rel_items = rel_items.replace('(#more)', rel_more);
			rel_items = rel_items.replace('(title)', rel_title);
			rel_subject_obj.innerHTML = rel_items;
		}
		
		/*if (fpCount && advInfo && advInfo.pLeft && advInfo.pRight) {
			if (advInfo.isShow || (advInfo.onlySrch && isFromSearchEngine())) {
				showAdv(advInfo);
			}
		}*/
		
		return true;
	}
	else {
		return false;
	}
}