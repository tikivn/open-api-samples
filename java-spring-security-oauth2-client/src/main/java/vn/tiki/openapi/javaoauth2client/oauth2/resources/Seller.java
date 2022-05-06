package vn.tiki.openapi.javaoauth2client.oauth2.resources;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
public class Seller implements Serializable {
    private String sid;
    private String name;
    private Boolean active;
    private String logo;
    private List<String> operationModels;
    private Boolean canUpdateProduct;
    private Boolean registrationStatus;
    private Date liveAt;
}
