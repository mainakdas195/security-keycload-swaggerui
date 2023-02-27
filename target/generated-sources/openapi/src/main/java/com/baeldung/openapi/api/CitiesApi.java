/**
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech) (5.3.1).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */
package com.baeldung.openapi.api;

import com.baeldung.openapi.model.CityDto;
import com.baeldung.openapi.model.Error;
import io.swagger.annotations.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.multipart.MultipartFile;

import javax.validation.Valid;
import javax.validation.constraints.*;
import java.util.List;
import java.util.Map;
import java.util.Optional;
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.SpringCodegen", date = "2023-02-23T17:27:41.905947700+05:30[Asia/Calcutta]")
@Validated
@Api(value = "cities", description = "the cities API")
public interface CitiesApi {

    default Optional<NativeWebRequest> getRequest() {
        return Optional.empty();
    }

    /**
     * GET /cities : List all cities
     *
     * @return list of cities (status code 200)
     *         or unexpected error (status code 200)
     */

    @ApiOperation(value = "List all cities", nickname = "getAllCities", notes = "", response = CityDto.class, responseContainer = "List", authorizations = {
        
        @Authorization(value = "bearerAuth")
         }, tags={ "City", })
    @ApiResponses(value = { 

        @ApiResponse(code = 200, message = "list of cities", response = CityDto.class, responseContainer = "List"),

        @ApiResponse(code = 200, message = "unexpected error", response = Error.class) })
    @RequestMapping(
        method = RequestMethod.GET,
        value = "/cities",
        produces = { "application/json" }
    )
    default ResponseEntity<List<CityDto>> _getAllCities() {
        return getAllCities();
    }

    // Override this method
    default  ResponseEntity<List<CityDto>> getAllCities() {
        getRequest().ifPresent(request -> {
            for (MediaType mediaType: MediaType.parseMediaTypes(request.getHeader("Accept"))) {
                if (mediaType.isCompatibleWith(MediaType.valueOf("application/json"))) {
                    String exampleString = "{ \"city_name\" : \"city_name\", \"city_id\" : 0 }";
                    ApiUtil.setExampleResponse(request, "application/json", exampleString);
                    break;
                }
            }
        });
        return new ResponseEntity<>(HttpStatus.NOT_IMPLEMENTED);

    }

}
