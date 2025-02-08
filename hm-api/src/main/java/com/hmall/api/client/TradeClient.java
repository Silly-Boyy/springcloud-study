package com.hmall.api.client;


import org.springframework.cloud.openfeign.FeignClient;

@FeignClient("trade-service")
public interface TradeClient {

}
