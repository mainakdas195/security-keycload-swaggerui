package com.baeldung.openapi.delegateimpl;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.baeldung.openapi.entity.City;
import com.baeldung.openapi.exception.BadRequestException;
import com.baeldung.openapi.exception.ExceptionConstant;
import com.baeldung.openapi.service.CityService;





@RestController
@RequestMapping("/demo")
public class DemoController {
	
	@Autowired
	CityService cityService;
	
	@GetMapping("/getCity")
	public List<String> getAllCity(){
		List<String> cities = new ArrayList<>();
		cities.add("INDIA");
		cities.add("NEPAL");
		cities.add("BHUTAN");
		
		return cities;
	}
	

	@GetMapping("/findAllCity")
	public List<City> getAllCities() throws Exception {
		List<City> empList = cityService.getAll();
		return empList;
	}
	

}
