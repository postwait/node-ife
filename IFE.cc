/* Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved. */

#ifndef BUILDING_NODE_EXTENSION
#define BUILDING_NODE_EXTENSION
#endif
#include <v8.h>

#include <node.h>
#include <stdio.h>
#include "ife.h"

#include "IFEheader.h"

namespace node {

  using namespace v8;

  static Persistent<String> emit_symbol;

  IFE::IFE() : ObjectWrap() {
  }
  
  IFE::~IFE() {
  }

  void IFE::emit(Local<Value> args[], int nargs) {
      Local<Value> emit_v = handle_->Get(emit_symbol);
      if (emit_v->IsFunction()) {
        Local<Function> emit = Local<Function>::Cast(emit_v);
        TryCatch tc;
        emit->Call(handle_, nargs, args);
        if (tc.HasCaught()) {
          // No nothing here.
        }
      }
  }
  Persistent<FunctionTemplate> IFE::constructor_template;
  
  void IFE::Initialize(Handle<Object> target) {
    HandleScope scope;

    Local<FunctionTemplate> t = FunctionTemplate::New(IFE::New);
    constructor_template = Persistent<FunctionTemplate>::New(t);
    constructor_template->InstanceTemplate()->SetInternalFieldCount(1);
    constructor_template->SetClassName(String::NewSymbol("IFE"));

    NODE_SET_PROTOTYPE_METHOD(constructor_template, "list", IFE::list);
    NODE_SET_PROTOTYPE_METHOD(constructor_template, "up", IFE::up);
    NODE_SET_PROTOTYPE_METHOD(constructor_template, "down", IFE::down);
    NODE_SET_PROTOTYPE_METHOD(constructor_template, "gratarp", IFE::gratarp);
    NODE_SET_PROTOTYPE_METHOD(constructor_template, "arpcache", IFE::arpcache);

    emit_symbol = NODE_PSYMBOL("emit");
    target->Set(String::NewSymbol("IFE"), constructor_template->GetFunction());
  }

  Handle<Value> IFE::New(const Arguments& args) {
    HandleScope scope;
    IFE *p = new IFE();

    p->Wrap(args.This());
    if(if_initialize()) return scope.Close(Undefined());

    if (args.Length() != 0) {
      return ThrowException(Exception::Error(String::New(
        "Must have no arguments")));
    }

    return args.This();
  }

  Handle<Value> IFE::arpcache(const Arguments& args) {
    HandleScope scope;
    int i, cnt;
    arp_entry *entries;

    cnt = sample_arp_cache(&entries);
    if(cnt < 0)
      return scope.Close(Undefined());
    Handle<Object> obj = Object::New();
    for(i=0;i<cnt;i++) {
      char ipstr[32], mac[20];
      unsigned char *m;
      if(inet_ntop(AF_INET, &entries[i].ipaddr, ipstr, sizeof(ipstr)) != NULL) {
        m = entries[i].mac;
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 m[0], m[1], m[2], m[3], m[4], m[5]);
        obj->Set(String::New(ipstr), String::New(mac));
      }
    }
    return scope.Close(obj);
  }

  Handle<Value> IFE::list(const Arguments& args) {
    int cnt, i;
    struct interface *ifs;
    HandleScope scope;
    
    ifs = (struct interface *)malloc(sizeof(*ifs) * 1024);
    cnt = if_list_ips(ifs, 1024);
    Handle<Array> obj = Array::New(cnt);
    for(i=0; i<cnt; i++) {
      char ipstr[64];
      Handle<Object> iface = Object::New();
      iface->Set(String::New("name"), String::New(ifs[i].ifname));
#define SET_IPV4(attr, name) do { \
  inet_ntop(AF_INET, &ifs[i].attr, ipstr, sizeof(ipstr)); \
  iface->Set(String::New(name), String::New(ipstr)); \
} while(0)
#define SET_IPV6(attr, name) do { \
  inet_ntop(AF_INET6, &ifs[i].attr, ipstr, sizeof(ipstr)); \
  iface->Set(String::New(name), String::New(ipstr)); \
} while(0)
      if(ifs[i].family == AF_INET6) {
        int len;
        SET_IPV6(ip6addr, "ip");
        len = set_prefix_from_netmask6(&ifs[i].netmask6);
        iface->Set(String::New("prefixlen"), Integer::New(len));
      } else {
        SET_IPV4(ipaddr, "ip");
        SET_IPV4(bcast, "broadcast");
        SET_IPV4(netmask, "netmask");
      }
      snprintf(ipstr, sizeof(ipstr), "%02x:%02x:%02x:%02x:%02x:%02x",
               ifs[i].mac[0], ifs[i].mac[1], ifs[i].mac[2],
               ifs[i].mac[3], ifs[i].mac[4], ifs[i].mac[5]);
      iface->Set(String::New("mac"), String::New(ipstr));
      obj->Set(Number::New(i), iface);
    }
    free(ifs);
    return scope.Close(obj);
  }

  Handle<Value> IFE::up(const Arguments& args) {
    HandleScope scope;
    struct interface iface;

    Handle<Object> obj = args.Holder();
    IFE *ife = ObjectWrap::Unwrap<IFE>(obj);

    memset((void *)&iface, 0, sizeof(iface));
    Local<Object> o = args[0]->ToObject();
    Local<Value> vname = o->Get(String::New("name"));
    if(vname->IsUndefined()) {
      ThrowException(Exception::TypeError(String::New("name: undefined")));
      return v8::Boolean::New(false);
    }
    Local<String> name = vname->ToString();
    String::Utf8Value ifname(name);
    strncpy(iface.ifname, *(ifname), IFNAMSIZ);

#define GET_IPV4(attr, name) do { \
    Local<Value> ovip = o->Get(String::New(name)); \
    if(ovip->IsUndefined()) { \
      ThrowException(Exception::TypeError(String::New(name ": undefined"))); \
      return v8::Boolean::New(false); \
    } \
    Local<String> addr = ovip->ToString(); \
    String::Utf8Value val(addr); \
    if(inet_pton(AF_INET, *(val), &iface.attr) != 1) { \
      ThrowException(Exception::TypeError(String::New(*val))); \
      return v8::Boolean::New(false); \
    } \
} while(0)

    Local<Value> vip = o->Get(String::New("ip"));
    if(vip->IsUndefined()) {
      ThrowException(Exception::TypeError(String::New("ip: undefined")));
      return v8::Boolean::New(false);
    }
    Local<String> ip = vip->ToString();
    String::Utf8Value ipval(ip);
    if(inet_pton(AF_INET, *(ipval), &iface.ipaddr) == 1) {
      GET_IPV4(bcast, "broadcast");
      GET_IPV4(netmask, "netmask");
      GET_IPV4(network, "network");
      iface.family = AF_INET;
    }
    else if(inet_pton(AF_INET6, *(ipval), &iface.ip6addr) == 1) {
      Local<Value> pname = o->Get(String::New("prefixlen"));
      Local<Integer> plen = pname->ToInteger();
      set_netmask6_from_prefix(&iface.netmask6, plen->Value());
      iface.family = AF_INET6;
    }
    else {
      ThrowException(Exception::TypeError(String::New(*ipval)));
      return v8::Boolean::New(false);
    }
    if(if_up(&iface)) {
      Local<Value> vChr[2];
      vChr[0] = String::New("error");
      vChr[1] = String::New(if_error());
      ife->emit(vChr, 2);
      return v8::Boolean::New(false);
    }
    return v8::Boolean::New(true);
  }

  Handle<Value> IFE::down(const Arguments& args) {
    HandleScope scope;
    struct interface iface;

    Handle<Object> obj = args.Holder();
    IFE *ife = ObjectWrap::Unwrap<IFE>(obj);
    memset((void *)&iface, 0, sizeof(iface));

    if(args[0]->IsUndefined()) {
      ThrowException(Exception::TypeError(String::New("argument undefined"))); \
      return scope.Close(Undefined());
    }
    Local<String> ip = args[0]->ToString();
    String::Utf8Value val(ip);
    if(inet_pton(AF_INET, *(val), &iface.ipaddr) == 1) {
      iface.family = AF_INET;
    }
    else if(inet_pton(AF_INET6, *(val), &iface.ip6addr) == 1) {
      iface.family = AF_INET6;
    }
    else {
      ThrowException(Exception::TypeError(String::New(*val)));
      return scope.Close(Undefined());
    }
    if(args.Length() == 2) {
      v8::String::AsciiValue val(args[1]);
      if(*val && strlen(*val) > 0 
        && strcmp(*val, "preplumbed")==0 ) {
          iface.state = ETH_DOWN_STATE;
      }
    }
    
    if(if_down(&iface)) {
      Local<Value> vChr[2];
      vChr[0] = String::New("error");
      vChr[1] = String::New(if_error());
      ife->emit(vChr, 2);
      return v8::Boolean::New(false);
    }
    return v8::Boolean::New(true);
  }

  Handle<Value> IFE::gratarp(const Arguments& args) {
    const char *dev;
    uint32_t my_ip, r_ip;
    int count = 1, do_ping = 1;
    unsigned char r_mac[ETH_ALEN];
    int good_mac = 0;
    HandleScope scope;

    Local<Object> o = args[0]->ToObject();
    Local<Value> vname = o->Get(String::New("name"));
    if(vname->IsUndefined()) {
      ThrowException(Exception::TypeError(String::New("name: undefined")));
      return v8::Boolean::New(false);
    }
    Local<String> name = vname->ToString();
    String::Utf8Value ifname(name);
    dev = *ifname;

    Local<Value> vmyip = o->Get(String::New("local_ip"));
    if(vmyip->IsUndefined()) {
      ThrowException(Exception::TypeError(String::New("local_ip: undefined")));
      return v8::Boolean::New(false);
    }
    Local<String> v8_myip = vmyip->ToString();
    String::Utf8Value val_myip(v8_myip);
    if(inet_pton(AF_INET, *(val_myip), &my_ip) != 1) {
      ThrowException(Exception::TypeError(String::New(*val_myip)));
      return v8::Boolean::New(false);
    }

    Local<Value> vrip = o->Get(String::New("remote_ip"));
    if(vrip->IsUndefined()) {
      ThrowException(Exception::TypeError(String::New("remote_ip: undefined")));
      return v8::Boolean::New(false);
    }
    Local<String> v8_rip = vrip->ToString();
    String::Utf8Value val_rip(v8_rip);
    if(inet_pton(AF_INET, *(val_rip), &r_ip) != 1) {
      ThrowException(Exception::Error(String::New(*val_rip)));
      return v8::Boolean::New(false);
    }

    Local<Value> vrmac = o->Get(String::New("remote_mac"));
    if(!vrmac->IsUndefined()) {
      int i;
      Local<String> v8_mac = vrmac->ToString();
      String::Utf8Value val_mac(v8_mac);
      if(strlen(*val_mac) == 17 &&
         (*(val_mac))[2] == ':' && (*(val_mac))[5] == ':' && (*(val_mac))[8] == ':' &&
         (*(val_mac))[11] == ':' && (*(val_mac))[14] == ':') {
        for(i=0;i<6;i++) {
          int v;
          if(sscanf((*(val_mac)) + i*3, "%02x", &v) == 1 && v >= 0 && v <= 255)
            r_mac[i] = (unsigned char) (v & 0xff);
          else
            break;
        }
        if(i == 6) good_mac = 1;
      }
      if(!good_mac) {
        ThrowException(Exception::Error(String::New("bad mac address")));
        return scope.Close(Undefined());
      }
    }

    if(args.Length() > 1) {
      if(!args[1]->IsNumber()) {
        ThrowException(Exception::TypeError(String::New("Second argument must be a number")));
        return scope.Close(Undefined());
      }
      count = args[1]->NumberValue();
    }

    if(args.Length() > 2) {
      if(!args[2]->IsBoolean()) {
        ThrowException(Exception::TypeError(String::New("Third argument must be a boolean")));
        return scope.Close(Undefined());
      }
      do_ping = args[2]->BooleanValue();
      if(do_ping && !good_mac) {
        ThrowException(Exception::Error(String::New("Can't do ping without remote mac")));
        return scope.Close(Undefined());
      }
    }

    count = if_send_spoof_request(dev, my_ip, r_ip, good_mac ? r_mac : NULL, count, do_ping);
    return scope.Close(Integer::New(count));
  }

  extern "C" void
  init(Handle<Object> target) {
    IFE::Initialize(target);
  }

  NODE_MODULE(IFEBinding, init)
} // namespace node
