using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ActionConstraints;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.WebHooks.ApplicationModels
{
    public class DefaultApplicationModelProvider : IApplicationModelProvider
    {
        private readonly MvcOptions _mvcOptions;
        private readonly IModelMetadataProvider _modelMetadataProvider;
        private readonly Func<ActionContext, bool> _supportsAllRequests;
        private readonly Func<ActionContext, bool> _supportsNonGetRequests;

        public DefaultApplicationModelProvider(
            IOptions<MvcOptions> mvcOptionsAccessor,
            IModelMetadataProvider modelMetadataProvider)
        {
            _mvcOptions = mvcOptionsAccessor.Value;
            _modelMetadataProvider = modelMetadataProvider;

            _supportsAllRequests = _ => true;
            _supportsNonGetRequests = context => !string.Equals(context.HttpContext.Request.Method, "GET", StringComparison.OrdinalIgnoreCase);
        }

        /// <inheritdoc />
        public int Order => -1000;

        /// <inheritdoc />
        public void OnProvidersExecuting(ApplicationModelProviderContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            foreach (var filter in _mvcOptions.Filters)
            {
                context.Result.Filters.Add(filter);
            }

            foreach (var controllerType in context.ControllerTypes)
            {
                var controllerModel = CreateControllerModel(controllerType);
                if (controllerModel == null)
                {
                    continue;
                }

                context.Result.Controllers.Add(controllerModel);
                controllerModel.Application = context.Result;

                foreach (var propertyHelper in PropertyHelper.GetProperties(controllerType.AsType()))
                {
                    var propertyInfo = propertyHelper.Property;
                    var propertyModel = CreatePropertyModel(propertyInfo);
                    if (propertyModel != null)
                    {
                        propertyModel.Controller = controllerModel;
                        controllerModel.ControllerProperties.Add(propertyModel);
                    }
                }

                foreach (var methodInfo in controllerType.AsType().GetMethods())
                {
                    var actionModel = CreateActionModel(controllerType, methodInfo);
                    if (actionModel == null)
                    {
                        continue;
                    }

                    actionModel.Controller = controllerModel;
                    controllerModel.Actions.Add(actionModel);

                    foreach (var parameterInfo in actionModel.ActionMethod.GetParameters())
                    {
                        var parameterModel = CreateParameterModel(parameterInfo);
                        if (parameterModel != null)
                        {
                            parameterModel.Action = actionModel;
                            actionModel.Parameters.Add(parameterModel);
                        }
                    }
                }
            }
        }

        /// <inheritdoc />
        public void OnProvidersExecuted(ApplicationModelProviderContext context)
        {
            // Intentionally empty.
        }

        /// <summary>
        /// Creates a <see cref="ControllerModel"/> for the given <see cref="TypeInfo"/>.
        /// </summary>
        /// <param name="typeInfo">The <see cref="TypeInfo"/>.</param>
        /// <returns>A <see cref="ControllerModel"/> for the given <see cref="TypeInfo"/>.</returns>
        internal ControllerModel CreateControllerModel(TypeInfo typeInfo)
        {
            if (typeInfo == null)
            {
                throw new ArgumentNullException(nameof(typeInfo));
            }

            // For attribute routes on a controller, we want to support 'overriding' routes on a derived
            // class. So we need to walk up the hierarchy looking for the first class to define routes.
            //
            // Then we want to 'filter' the set of attributes, so that only the effective routes apply.
            var currentTypeInfo = typeInfo;
            var objectTypeInfo = typeof(object).GetTypeInfo();

            IRouteTemplateProvider[] routeAttributes;

            do
            {
                routeAttributes = currentTypeInfo
                    .GetCustomAttributes(inherit: false)
                    .OfType<IRouteTemplateProvider>()
                    .ToArray();

                if (routeAttributes.Length > 0)
                {
                    // Found 1 or more route attributes.
                    break;
                }

                currentTypeInfo = currentTypeInfo.BaseType.GetTypeInfo();
            }
            while (currentTypeInfo != objectTypeInfo);

            // CoreCLR returns IEnumerable<Attribute> from GetCustomAttributes - the OfType<object>
            // is needed to so that the result of ToArray() is object
            var attributes = typeInfo.GetCustomAttributes(inherit: true);

            // This is fairly complicated so that we maintain referential equality between items in
            // ControllerModel.Attributes and ControllerModel.Attributes[*].Attribute.
            var filteredAttributes = new List<object>();
            foreach (var attribute in attributes)
            {
                if (attribute is IRouteTemplateProvider)
                {
                    // This attribute is a route-attribute, leave it out.
                }
                else
                {
                    filteredAttributes.Add(attribute);
                }
            }

            filteredAttributes.AddRange(routeAttributes);

            attributes = filteredAttributes.ToArray();

            var controllerModel = new ControllerModel(typeInfo, attributes);

            AddRange(controllerModel.Selectors, CreateSelectors(attributes));

            controllerModel.ControllerName =
                typeInfo.Name.EndsWith("Controller", StringComparison.OrdinalIgnoreCase) ?
                    typeInfo.Name.Substring(0, typeInfo.Name.Length - "Controller".Length) :
                    typeInfo.Name;

            AddRange(controllerModel.Filters, attributes.OfType<IFilterMetadata>());

            foreach (var routeValueProvider in attributes.OfType<IRouteValueProvider>())
            {
                controllerModel.RouteValues.Add(routeValueProvider.RouteKey, routeValueProvider.RouteValue);
            }

            var apiVisibility = attributes.OfType<IApiDescriptionVisibilityProvider>().FirstOrDefault();
            if (apiVisibility != null)
            {
                controllerModel.ApiExplorer.IsVisible = !apiVisibility.IgnoreApi;
            }

            var apiGroupName = attributes.OfType<IApiDescriptionGroupNameProvider>().FirstOrDefault();
            if (apiGroupName != null)
            {
                controllerModel.ApiExplorer.GroupName = apiGroupName.GroupName;
            }

            // Controllers can implement action filter and result filter interfaces. We add
            // a special delegating filter implementation to the pipeline to handle it.
            //
            // This is needed because filters are instantiated before the controller.
            if (typeof(IAsyncActionFilter).GetTypeInfo().IsAssignableFrom(typeInfo) ||
                typeof(IActionFilter).GetTypeInfo().IsAssignableFrom(typeInfo))
            {
                controllerModel.Filters.Add(new ControllerActionFilter());
            }
            if (typeof(IAsyncResultFilter).GetTypeInfo().IsAssignableFrom(typeInfo) ||
                typeof(IResultFilter).GetTypeInfo().IsAssignableFrom(typeInfo))
            {
                controllerModel.Filters.Add(new ControllerResultFilter());
            }

            return controllerModel;
        }

        /// <summary>
        /// Creates a <see cref="PropertyModel"/> for the given <see cref="PropertyInfo"/>.
        /// </summary>
        /// <param name="propertyInfo">The <see cref="PropertyInfo"/>.</param>
        /// <returns>A <see cref="PropertyModel"/> for the given <see cref="PropertyInfo"/>.</returns>
        internal PropertyModel CreatePropertyModel(PropertyInfo propertyInfo)
        {
            if (propertyInfo == null)
            {
                throw new ArgumentNullException(nameof(propertyInfo));
            }

            var attributes = propertyInfo.GetCustomAttributes(inherit: true);

            // BindingInfo for properties can be either specified by decorating the property with binding specific attributes.
            // ModelMetadata also adds information from the property's type and any configured IBindingMetadataProvider.
            var modelMetadata = _modelMetadataProvider.GetMetadataForProperty(propertyInfo.DeclaringType, propertyInfo.Name);
            var bindingInfo = BindingInfo.GetBindingInfo(attributes, modelMetadata);

            if (bindingInfo == null)
            {
                // Look for BindPropertiesAttribute on the handler type if no BindingInfo was inferred for the property.
                // This allows a user to enable model binding on properties by decorating the controller type with BindPropertiesAttribute.
                var declaringType = propertyInfo.DeclaringType;
                var bindPropertiesAttribute = declaringType.GetCustomAttribute<BindPropertiesAttribute>(inherit: true);
                if (bindPropertiesAttribute != null)
                {
                    var requestPredicate = bindPropertiesAttribute.SupportsGet ? _supportsAllRequests : _supportsNonGetRequests;
                    bindingInfo = new BindingInfo
                    {
                        RequestPredicate = requestPredicate,
                    };
                }
            }

            var propertyModel = new PropertyModel(propertyInfo, attributes)
            {
                PropertyName = propertyInfo.Name,
                BindingInfo = bindingInfo,
            };

            return propertyModel;
        }

        /// <summary>
        /// Creates the <see cref="ActionModel"/> instance for the given action <see cref="MethodInfo"/>.
        /// </summary>
        /// <param name="typeInfo">The controller <see cref="TypeInfo"/>.</param>
        /// <param name="methodInfo">The action <see cref="MethodInfo"/>.</param>
        /// <returns>
        /// An <see cref="ActionModel"/> instance for the given action <see cref="MethodInfo"/> or
        /// <c>null</c> if the <paramref name="methodInfo"/> does not represent an action.
        /// </returns>
        internal ActionModel CreateActionModel(
            TypeInfo typeInfo,
            MethodInfo methodInfo)
        {
            if (typeInfo == null)
            {
                throw new ArgumentNullException(nameof(typeInfo));
            }

            if (methodInfo == null)
            {
                throw new ArgumentNullException(nameof(methodInfo));
            }

            if (!IsAction(typeInfo, methodInfo))
            {
                return null;
            }

            // CoreCLR returns IEnumerable<Attribute> from GetCustomAttributes - the OfType<object>
            // is needed to so that the result of ToArray() is object
            var attributes = methodInfo.GetCustomAttributes(inherit: true);

            var actionModel = new ActionModel(methodInfo, attributes);

            AddRange(actionModel.Filters, attributes.OfType<IFilterMetadata>());

            var actionName = attributes.OfType<ActionNameAttribute>().FirstOrDefault();
            if (actionName?.Name != null)
            {
                actionModel.ActionName = actionName.Name;
            }
            else
            {
                actionModel.ActionName = CanonicalizeActionName(methodInfo.Name);
            }

            var apiVisibility = attributes.OfType<IApiDescriptionVisibilityProvider>().FirstOrDefault();
            if (apiVisibility != null)
            {
                actionModel.ApiExplorer.IsVisible = !apiVisibility.IgnoreApi;
            }

            var apiGroupName = attributes.OfType<IApiDescriptionGroupNameProvider>().FirstOrDefault();
            if (apiGroupName != null)
            {
                actionModel.ApiExplorer.GroupName = apiGroupName.GroupName;
            }

            foreach (var routeValueProvider in attributes.OfType<IRouteValueProvider>())
            {
                actionModel.RouteValues.Add(routeValueProvider.RouteKey, routeValueProvider.RouteValue);
            }

            // Now we need to determine the action selection info (cross-section of routes and constraints)
            //
            // For attribute routes on a action, we want to support 'overriding' routes on a
            // virtual method, but allow 'overriding'. So we need to walk up the hierarchy looking
            // for the first definition to define routes.
            //
            // Then we want to 'filter' the set of attributes, so that only the effective routes apply.
            var currentMethodInfo = methodInfo;

            IRouteTemplateProvider[] routeAttributes;

            while (true)
            {
                routeAttributes = currentMethodInfo
                    .GetCustomAttributes(inherit: false)
                    .OfType<IRouteTemplateProvider>()
                    .ToArray();

                if (routeAttributes.Length > 0)
                {
                    // Found 1 or more route attributes.
                    break;
                }

                // GetBaseDefinition returns 'this' when it gets to the bottom of the chain.
                var nextMethodInfo = currentMethodInfo.GetBaseDefinition();
                if (currentMethodInfo == nextMethodInfo)
                {
                    break;
                }

                currentMethodInfo = nextMethodInfo;
            }

            // This is fairly complicated so that we maintain referential equality between items in
            // ActionModel.Attributes and ActionModel.Attributes[*].Attribute.
            var applicableAttributes = new List<object>();
            foreach (var attribute in attributes)
            {
                if (attribute is IRouteTemplateProvider)
                {
                    // This attribute is a route-attribute, leave it out.
                }
                else
                {
                    applicableAttributes.Add(attribute);
                }
            }

            applicableAttributes.AddRange(routeAttributes);
            AddRange(actionModel.Selectors, CreateSelectors(applicableAttributes));

            return actionModel;
        }

        private string CanonicalizeActionName(string actionName)
        {
            const string Suffix = "Async";

            if (_mvcOptions.SuppressAsyncSuffixInActionNames &&
                actionName.EndsWith(Suffix, StringComparison.Ordinal))
            {
                actionName = actionName.Substring(0, actionName.Length - Suffix.Length);
            }

            return actionName;
        }

        /// <summary>
        /// Returns <c>true</c> if the <paramref name="methodInfo"/> is an action. Otherwise <c>false</c>.
        /// </summary>
        /// <param name="typeInfo">The <see cref="TypeInfo"/>.</param>
        /// <param name="methodInfo">The <see cref="MethodInfo"/>.</param>
        /// <returns><c>true</c> if the <paramref name="methodInfo"/> is an action. Otherwise <c>false</c>.</returns>
        /// <remarks>
        /// Override this method to provide custom logic to determine which methods are considered actions.
        /// </remarks>
        internal bool IsAction(TypeInfo typeInfo, MethodInfo methodInfo)
        {
            if (typeInfo == null)
            {
                throw new ArgumentNullException(nameof(typeInfo));
            }

            if (methodInfo == null)
            {
                throw new ArgumentNullException(nameof(methodInfo));
            }

            // The SpecialName bit is set to flag members that are treated in a special way by some compilers
            // (such as property accessors and operator overloading methods).
            if (methodInfo.IsSpecialName)
            {
                return false;
            }

            if (methodInfo.IsDefined(typeof(NonActionAttribute)))
            {
                return false;
            }

            // Overridden methods from Object class, e.g. Equals(Object), GetHashCode(), etc., are not valid.
            if (methodInfo.GetBaseDefinition().DeclaringType == typeof(object))
            {
                return false;
            }

            // Dispose method implemented from IDisposable is not valid
            if (IsIDisposableMethod(methodInfo))
            {
                return false;
            }

            if (methodInfo.IsStatic)
            {
                return false;
            }

            if (methodInfo.IsAbstract)
            {
                return false;
            }

            if (methodInfo.IsConstructor)
            {
                return false;
            }

            if (methodInfo.IsGenericMethod)
            {
                return false;
            }

            return methodInfo.IsPublic;
        }

        /// <summary>
        /// Creates a <see cref="ParameterModel"/> for the given <see cref="ParameterInfo"/>.
        /// </summary>
        /// <param name="parameterInfo">The <see cref="ParameterInfo"/>.</param>
        /// <returns>A <see cref="ParameterModel"/> for the given <see cref="ParameterInfo"/>.</returns>
        internal ParameterModel CreateParameterModel(ParameterInfo parameterInfo)
        {
            if (parameterInfo == null)
            {
                throw new ArgumentNullException(nameof(parameterInfo));
            }

            var attributes = parameterInfo.GetCustomAttributes(inherit: true);

            BindingInfo bindingInfo;
            if (_modelMetadataProvider is ModelMetadataProvider modelMetadataProviderBase)
            {
                var modelMetadata = modelMetadataProviderBase.GetMetadataForParameter(parameterInfo);
                bindingInfo = BindingInfo.GetBindingInfo(attributes, modelMetadata);
            }
            else
            {
                // GetMetadataForParameter should only be used if the user has opted in to the 2.1 behavior.
                bindingInfo = BindingInfo.GetBindingInfo(attributes);
            }

            var parameterModel = new ParameterModel(parameterInfo, attributes)
            {
                ParameterName = parameterInfo.Name,
                BindingInfo = bindingInfo,
            };

            return parameterModel;
        }

        private IList<SelectorModel> CreateSelectors(IList<object> attributes)
        {
            // Route attributes create multiple selector models, we want to split the set of
            // attributes based on these so each selector only has the attributes that affect it.
            //
            // The set of route attributes are split into those that 'define' a route versus those that are
            // 'silent'.
            //
            // We need to define a selector for each attribute that 'defines' a route, and a single selector
            // for all of the ones that don't (if any exist).
            //
            // If the attribute that 'defines' a route is NOT an IActionHttpMethodProvider, then we'll include with
            // it, any IActionHttpMethodProvider that are 'silent' IRouteTemplateProviders. In this case the 'extra'
            // action for silent route providers isn't needed.
            //
            // Ex:
            // [HttpGet]
            // [AcceptVerbs("POST", "PUT")]
            // [HttpPost("Api/Things")]
            // public void DoThing()
            //
            // This will generate 2 selectors:
            // 1. [HttpPost("Api/Things")]
            // 2. [HttpGet], [AcceptVerbs("POST", "PUT")]
            //
            // Another example of this situation is:
            //
            // [Route("api/Products")]
            // [AcceptVerbs("GET", "HEAD")]
            // [HttpPost("api/Products/new")]
            //
            // This will generate 2 selectors:
            // 1. [AcceptVerbs("GET", "HEAD")]
            // 2. [HttpPost]
            //
            // Note that having a route attribute that doesn't define a route template _might_ be an error. We
            // don't have enough context to really know at this point so we just pass it on.
            var routeProviders = new List<IRouteTemplateProvider>();

            var createSelectorForSilentRouteProviders = false;
            foreach (var attribute in attributes)
            {
                if (attribute is IRouteTemplateProvider routeTemplateProvider)
                {
                    if (IsSilentRouteAttribute(routeTemplateProvider))
                    {
                        createSelectorForSilentRouteProviders = true;
                    }
                    else
                    {
                        routeProviders.Add(routeTemplateProvider);
                    }
                }
            }

            foreach (var routeProvider in routeProviders)
            {
                // If we see an attribute like
                // [Route(...)]
                //
                // Then we want to group any attributes like [HttpGet] with it.
                //
                // Basically...
                //
                // [HttpGet]
                // [HttpPost("Products")]
                // public void Foo() { }
                //
                // Is two selectors. And...
                //
                // [HttpGet]
                // [Route("Products")]
                // public void Foo() { }
                //
                // Is one selector.
                if (!(routeProvider is IActionHttpMethodProvider))
                {
                    createSelectorForSilentRouteProviders = false;
                    break;
                }
            }

            var selectorModels = new List<SelectorModel>();
            if (routeProviders.Count == 0 && !createSelectorForSilentRouteProviders)
            {
                // Simple case, all attributes apply
                selectorModels.Add(CreateSelectorModel(route: null, attributes: attributes));
            }
            else
            {
                // Each of these routeProviders are the ones that actually have routing information on them
                // something like [HttpGet] won't show up here, but [HttpGet("Products")] will.
                foreach (var routeProvider in routeProviders)
                {
                    var filteredAttributes = new List<object>();
                    foreach (var attribute in attributes)
                    {
                        if (ReferenceEquals(attribute, routeProvider))
                        {
                            filteredAttributes.Add(attribute);
                        }
                        else if (InRouteProviders(routeProviders, attribute))
                        {
                            // Exclude other route template providers
                            // Example:
                            // [HttpGet("template")]
                            // [Route("template/{id}")]
                        }
                        else if (
                            routeProvider is IActionHttpMethodProvider &&
                            attribute is IActionHttpMethodProvider)
                        {
                            // Example:
                            // [HttpGet("template")]
                            // [AcceptVerbs("GET", "POST")]
                            //
                            // Exclude other http method providers if this route is an
                            // http method provider.
                        }
                        else
                        {
                            filteredAttributes.Add(attribute);
                        }
                    }

                    selectorModels.Add(CreateSelectorModel(routeProvider, filteredAttributes));
                }

                if (createSelectorForSilentRouteProviders)
                {
                    var filteredAttributes = new List<object>();
                    foreach (var attribute in attributes)
                    {
                        if (!InRouteProviders(routeProviders, attribute))
                        {
                            filteredAttributes.Add(attribute);
                        }
                    }

                    selectorModels.Add(CreateSelectorModel(route: null, attributes: filteredAttributes));
                }
            }

            return selectorModels;
        }

        private static bool InRouteProviders(List<IRouteTemplateProvider> routeProviders, object attribute)
        {
            foreach (var rp in routeProviders)
            {
                if (ReferenceEquals(rp, attribute))
                {
                    return true;
                }
            }

            return false;
        }

        private static SelectorModel CreateSelectorModel(IRouteTemplateProvider route, IList<object> attributes)
        {
            var selectorModel = new SelectorModel();
            if (route != null)
            {
                selectorModel.AttributeRouteModel = new AttributeRouteModel(route);
            }

            AddRange(selectorModel.ActionConstraints, attributes.OfType<IActionConstraintMetadata>());
            AddRange(selectorModel.EndpointMetadata, attributes);

            // Simple case, all HTTP method attributes apply
            var httpMethods = attributes
                .OfType<IActionHttpMethodProvider>()
                .SelectMany(a => a.HttpMethods)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (httpMethods.Length > 0)
            {
                selectorModel.ActionConstraints.Add(new HttpMethodActionConstraint(httpMethods));
                selectorModel.EndpointMetadata.Add(new HttpMethodMetadata(httpMethods));
            }

            return selectorModel;
        }

        private bool IsIDisposableMethod(MethodInfo methodInfo)
        {
            // Ideally we do not want Dispose method to be exposed as an action. However there are some scenarios where a user
            // might want to expose a method with name "Dispose" (even though they might not be really disposing resources)
            // Example: A controller deriving from MVC's Controller type might wish to have a method with name Dispose,
            // in which case they can use the "new" keyword to hide the base controller's declaration.

            // Find where the method was originally declared
            var baseMethodInfo = methodInfo.GetBaseDefinition();
            var declaringTypeInfo = baseMethodInfo.DeclaringType.GetTypeInfo();

            return
                (typeof(IDisposable).GetTypeInfo().IsAssignableFrom(declaringTypeInfo) &&
                 declaringTypeInfo.GetRuntimeInterfaceMap(typeof(IDisposable)).TargetMethods[0] == baseMethodInfo);
        }

        private bool IsSilentRouteAttribute(IRouteTemplateProvider routeTemplateProvider)
        {
            return
                routeTemplateProvider.Template == null &&
                routeTemplateProvider.Order == null &&
                routeTemplateProvider.Name == null;
        }

        private static void AddRange<T>(IList<T> list, IEnumerable<T> items)
        {
            foreach (var item in items)
            {
                list.Add(item);
            }
        }
    }

    /// <summary>
    /// A filter implementation which delegates to the controller for action filter interfaces.
    /// </summary>
    public class ControllerActionFilter : IAsyncActionFilter, IOrderedFilter
    {
        // Controller-filter methods run farthest from the action by default.
        /// <inheritdoc />
        public int Order { get; set; } = int.MinValue;

        /// <inheritdoc />
        public Task OnActionExecutionAsync(
            ActionExecutingContext context,
            ActionExecutionDelegate next)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (next == null)
            {
                throw new ArgumentNullException(nameof(next));
            }

            var controller = context.Controller;
            if (controller == null)
            {
                throw new InvalidOperationException(
                    $"{nameof(context.Controller)} {nameof(ActionExecutingContext)}");
            }

            if (controller is IAsyncActionFilter asyncActionFilter)
            {
                return asyncActionFilter.OnActionExecutionAsync(context, next);
            }
            else if (controller is IActionFilter actionFilter)
            {
                return ExecuteActionFilter(context, next, actionFilter);
            }
            else
            {
                return next();
            }
        }

        private static async Task ExecuteActionFilter(
            ActionExecutingContext context,
            ActionExecutionDelegate next,
            IActionFilter actionFilter)
        {
            actionFilter.OnActionExecuting(context);
            if (context.Result == null)
            {
                actionFilter.OnActionExecuted(await next());
            }
        }
    }

    /// <summary>
    /// A filter implementation which delegates to the controller for result filter interfaces.
    /// </summary>
    public class ControllerResultFilter : IAsyncResultFilter, IOrderedFilter
    {
        // Controller-filter methods run farthest from the result by default.
        /// <inheritdoc />
        public int Order { get; set; } = int.MinValue;

        /// <inheritdoc />
        public Task OnResultExecutionAsync(
            ResultExecutingContext context,
            ResultExecutionDelegate next)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (next == null)
            {
                throw new ArgumentNullException(nameof(next));
            }

            var controller = context.Controller;
            if (controller == null)
            {
                throw new InvalidOperationException($"{nameof(context.Controller)} {nameof(ResultExecutingContext)}");
            }

            if (controller is IAsyncResultFilter asyncResultFilter)
            {
                return asyncResultFilter.OnResultExecutionAsync(context, next);
            }
            else if (controller is IResultFilter resultFilter)
            {
                return ExecuteResultFilter(context, next, resultFilter);
            }
            else
            {
                return next();
            }
        }

        private static async Task ExecuteResultFilter(
            ResultExecutingContext context,
            ResultExecutionDelegate next,
            IResultFilter resultFilter)
        {
            resultFilter.OnResultExecuting(context);
            if (!context.Cancel)
            {
                resultFilter.OnResultExecuted(await next());
            }
        }
    }

    public class PropertyHelper
    {
        // Delegate type for a by-ref property getter
        private delegate TValue ByRefFunc<TDeclaringType, TValue>(ref TDeclaringType arg);

        private static readonly MethodInfo CallPropertyGetterOpenGenericMethod =
            typeof(PropertyHelper).GetTypeInfo().GetDeclaredMethod(nameof(CallPropertyGetter));

        private static readonly MethodInfo CallPropertyGetterByReferenceOpenGenericMethod =
            typeof(PropertyHelper).GetTypeInfo().GetDeclaredMethod(nameof(CallPropertyGetterByReference));

        private static readonly MethodInfo CallNullSafePropertyGetterOpenGenericMethod =
            typeof(PropertyHelper).GetTypeInfo().GetDeclaredMethod(nameof(CallNullSafePropertyGetter));

        private static readonly MethodInfo CallNullSafePropertyGetterByReferenceOpenGenericMethod =
            typeof(PropertyHelper).GetTypeInfo().GetDeclaredMethod(nameof(CallNullSafePropertyGetterByReference));

        private static readonly MethodInfo CallPropertySetterOpenGenericMethod =
            typeof(PropertyHelper).GetTypeInfo().GetDeclaredMethod(nameof(CallPropertySetter));

        // Using an array rather than IEnumerable, as target will be called on the hot path numerous times.
        private static readonly ConcurrentDictionary<Type, PropertyHelper[]> PropertiesCache =
            new ConcurrentDictionary<Type, PropertyHelper[]>();

        private static readonly ConcurrentDictionary<Type, PropertyHelper[]> VisiblePropertiesCache =
            new ConcurrentDictionary<Type, PropertyHelper[]>();

        // We need to be able to check if a type is a 'ref struct' - but we need to be able to compile
        // for platforms where the attribute is not defined, like net46. So we can fetch the attribute
        // by late binding. If the attribute isn't defined, then we assume we won't encounter any
        // 'ref struct' types.
        private static readonly Type IsByRefLikeAttribute = Type.GetType("System.Runtime.CompilerServices.IsByRefLikeAttribute", throwOnError: false);

        private Action<object, object> _valueSetter;
        private Func<object, object> _valueGetter;

        /// <summary>
        /// Initializes a fast <see cref="PropertyHelper"/>.
        /// This constructor does not cache the helper. For caching, use <see cref="GetProperties(Type)"/>.
        /// </summary>
        public PropertyHelper(PropertyInfo property)
        {
            Property = property ?? throw new ArgumentNullException(nameof(property));
            Name = property.Name;
        }

        /// <summary>
        /// Gets the backing <see cref="PropertyInfo"/>.
        /// </summary>
        public PropertyInfo Property { get; }

        /// <summary>
        /// Gets (or sets in derived types) the property name.
        /// </summary>
        public virtual string Name { get; protected set; }

        /// <summary>
        /// Gets the property value getter.
        /// </summary>
        public Func<object, object> ValueGetter
        {
            get
            {
                if (_valueGetter == null)
                {
                    _valueGetter = MakeFastPropertyGetter(Property);
                }

                return _valueGetter;
            }
        }

        /// <summary>
        /// Gets the property value setter.
        /// </summary>
        public Action<object, object> ValueSetter
        {
            get
            {
                if (_valueSetter == null)
                {
                    _valueSetter = MakeFastPropertySetter(Property);
                }

                return _valueSetter;
            }
        }

        /// <summary>
        /// Returns the property value for the specified <paramref name="instance"/>.
        /// </summary>
        /// <param name="instance">The object whose property value will be returned.</param>
        /// <returns>The property value.</returns>
        public object GetValue(object instance)
        {
            return ValueGetter(instance);
        }

        /// <summary>
        /// Sets the property value for the specified <paramref name="instance" />.
        /// </summary>
        /// <param name="instance">The object whose property value will be set.</param>
        /// <param name="value">The property value.</param>
        public void SetValue(object instance, object value)
        {
            ValueSetter(instance, value);
        }

        /// <summary>
        /// Creates and caches fast property helpers that expose getters for every public get property on the
        /// underlying type.
        /// </summary>
        /// <param name="typeInfo">The type info to extract property accessors for.</param>
        /// <returns>A cached array of all public properties of the specified type.
        /// </returns>
        public static PropertyHelper[] GetProperties(TypeInfo typeInfo)
        {
            return GetProperties(typeInfo.AsType());
        }

        /// <summary>
        /// Creates and caches fast property helpers that expose getters for every public get property on the
        /// specified type.
        /// </summary>
        /// <param name="type">The type to extract property accessors for.</param>
        /// <returns>A cached array of all public properties of the specified type.
        /// </returns>
        public static PropertyHelper[] GetProperties(Type type)
        {
            return GetProperties(type, p => CreateInstance(p), PropertiesCache);
        }

        /// <summary>
        /// <para>
        /// Creates and caches fast property helpers that expose getters for every non-hidden get property
        /// on the specified type.
        /// </para>
        /// <para>
        /// <see cref="M:GetVisibleProperties"/> excludes properties defined on base types that have been
        /// hidden by definitions using the <c>new</c> keyword.
        /// </para>
        /// </summary>
        /// <param name="typeInfo">The type info to extract property accessors for.</param>
        /// <returns>
        /// A cached array of all public properties of the specified type.
        /// </returns>
        public static PropertyHelper[] GetVisibleProperties(TypeInfo typeInfo)
        {
            return GetVisibleProperties(typeInfo.AsType(), p => CreateInstance(p), PropertiesCache, VisiblePropertiesCache);
        }

        /// <summary>
        /// <para>
        /// Creates and caches fast property helpers that expose getters for every non-hidden get property
        /// on the specified type.
        /// </para>
        /// <para>
        /// <see cref="M:GetVisibleProperties"/> excludes properties defined on base types that have been
        /// hidden by definitions using the <c>new</c> keyword.
        /// </para>
        /// </summary>
        /// <param name="type">The type to extract property accessors for.</param>
        /// <returns>
        /// A cached array of all public properties of the specified type.
        /// </returns>
        public static PropertyHelper[] GetVisibleProperties(Type type)
        {
            return GetVisibleProperties(type, p => CreateInstance(p), PropertiesCache, VisiblePropertiesCache);
        }

        /// <summary>
        /// Creates a single fast property getter. The result is not cached.
        /// </summary>
        /// <param name="propertyInfo">propertyInfo to extract the getter for.</param>
        /// <returns>a fast getter.</returns>
        /// <remarks>
        /// This method is more memory efficient than a dynamically compiled lambda, and about the
        /// same speed.
        /// </remarks>
        public static Func<object, object> MakeFastPropertyGetter(PropertyInfo propertyInfo)
        {
            Debug.Assert(propertyInfo != null);

            return MakeFastPropertyGetter(
                propertyInfo,
                CallPropertyGetterOpenGenericMethod,
                CallPropertyGetterByReferenceOpenGenericMethod);
        }

        /// <summary>
        /// Creates a single fast property getter which is safe for a null input object. The result is not cached.
        /// </summary>
        /// <param name="propertyInfo">propertyInfo to extract the getter for.</param>
        /// <returns>a fast getter.</returns>
        /// <remarks>
        /// This method is more memory efficient than a dynamically compiled lambda, and about the
        /// same speed.
        /// </remarks>
        public static Func<object, object> MakeNullSafeFastPropertyGetter(PropertyInfo propertyInfo)
        {
            Debug.Assert(propertyInfo != null);

            return MakeFastPropertyGetter(
                propertyInfo,
                CallNullSafePropertyGetterOpenGenericMethod,
                CallNullSafePropertyGetterByReferenceOpenGenericMethod);
        }

        private static Func<object, object> MakeFastPropertyGetter(
            PropertyInfo propertyInfo,
            MethodInfo propertyGetterWrapperMethod,
            MethodInfo propertyGetterByRefWrapperMethod)
        {
            Debug.Assert(propertyInfo != null);

            // Must be a generic method with a Func<,> parameter
            Debug.Assert(propertyGetterWrapperMethod != null);
            Debug.Assert(propertyGetterWrapperMethod.IsGenericMethodDefinition);
            Debug.Assert(propertyGetterWrapperMethod.GetParameters().Length == 2);

            // Must be a generic method with a ByRefFunc<,> parameter
            Debug.Assert(propertyGetterByRefWrapperMethod != null);
            Debug.Assert(propertyGetterByRefWrapperMethod.IsGenericMethodDefinition);
            Debug.Assert(propertyGetterByRefWrapperMethod.GetParameters().Length == 2);

            var getMethod = propertyInfo.GetMethod;
            Debug.Assert(getMethod != null);
            Debug.Assert(!getMethod.IsStatic);
            Debug.Assert(getMethod.GetParameters().Length == 0);

            // Instance methods in the CLR can be turned into static methods where the first parameter
            // is open over "target". This parameter is always passed by reference, so we have a code
            // path for value types and a code path for reference types.
            if (getMethod.DeclaringType.GetTypeInfo().IsValueType)
            {
                // Create a delegate (ref TDeclaringType) -> TValue
                return MakeFastPropertyGetter(
                    typeof(ByRefFunc<,>),
                    getMethod,
                    propertyGetterByRefWrapperMethod);
            }
            else
            {
                // Create a delegate TDeclaringType -> TValue
                return MakeFastPropertyGetter(
                    typeof(Func<,>),
                    getMethod,
                    propertyGetterWrapperMethod);
            }
        }

        private static Func<object, object> MakeFastPropertyGetter(
            Type openGenericDelegateType,
            MethodInfo propertyGetMethod,
            MethodInfo openGenericWrapperMethod)
        {
            var typeInput = propertyGetMethod.DeclaringType;
            var typeOutput = propertyGetMethod.ReturnType;

            var delegateType = openGenericDelegateType.MakeGenericType(typeInput, typeOutput);
            var propertyGetterDelegate = propertyGetMethod.CreateDelegate(delegateType);

            var wrapperDelegateMethod = openGenericWrapperMethod.MakeGenericMethod(typeInput, typeOutput);
            var accessorDelegate = wrapperDelegateMethod.CreateDelegate(
                typeof(Func<object, object>),
                propertyGetterDelegate);

            return (Func<object, object>)accessorDelegate;
        }

        /// <summary>
        /// Creates a single fast property setter for reference types. The result is not cached.
        /// </summary>
        /// <param name="propertyInfo">propertyInfo to extract the setter for.</param>
        /// <returns>a fast getter.</returns>
        /// <remarks>
        /// This method is more memory efficient than a dynamically compiled lambda, and about the
        /// same speed. This only works for reference types.
        /// </remarks>
        public static Action<object, object> MakeFastPropertySetter(PropertyInfo propertyInfo)
        {
            Debug.Assert(propertyInfo != null);
            Debug.Assert(!propertyInfo.DeclaringType.GetTypeInfo().IsValueType);

            var setMethod = propertyInfo.SetMethod;
            Debug.Assert(setMethod != null);
            Debug.Assert(!setMethod.IsStatic);
            Debug.Assert(setMethod.ReturnType == typeof(void));
            var parameters = setMethod.GetParameters();
            Debug.Assert(parameters.Length == 1);

            // Instance methods in the CLR can be turned into static methods where the first parameter
            // is open over "target". This parameter is always passed by reference, so we have a code
            // path for value types and a code path for reference types.
            var typeInput = setMethod.DeclaringType;
            var parameterType = parameters[0].ParameterType;

            // Create a delegate TDeclaringType -> { TDeclaringType.Property = TValue; }
            var propertySetterAsAction =
                setMethod.CreateDelegate(typeof(Action<,>).MakeGenericType(typeInput, parameterType));
            var callPropertySetterClosedGenericMethod =
                CallPropertySetterOpenGenericMethod.MakeGenericMethod(typeInput, parameterType);
            var callPropertySetterDelegate =
                callPropertySetterClosedGenericMethod.CreateDelegate(
                    typeof(Action<object, object>), propertySetterAsAction);

            return (Action<object, object>)callPropertySetterDelegate;
        }

        /// <summary>
        /// Given an object, adds each instance property with a public get method as a key and its
        /// associated value to a dictionary.
        ///
        /// If the object is already an <see cref="IDictionary{String, Object}"/> instance, then a copy
        /// is returned.
        /// </summary>
        /// <remarks>
        /// The implementation of PropertyHelper will cache the property accessors per-type. This is
        /// faster when the same type is used multiple times with ObjectToDictionary.
        /// </remarks>
        public static IDictionary<string, object> ObjectToDictionary(object value)
        {
            var dictionary = value as IDictionary<string, object>;
            if (dictionary != null)
            {
                return new Dictionary<string, object>(dictionary, StringComparer.OrdinalIgnoreCase);
            }

            dictionary = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);

            if (value != null)
            {
                foreach (var helper in GetProperties(value.GetType()))
                {
                    dictionary[helper.Name] = helper.GetValue(value);
                }
            }

            return dictionary;
        }

        private static PropertyHelper CreateInstance(PropertyInfo property)
        {
            return new PropertyHelper(property);
        }

        // Called via reflection
        private static object CallPropertyGetter<TDeclaringType, TValue>(
            Func<TDeclaringType, TValue> getter,
            object target)
        {
            return getter((TDeclaringType)target);
        }

        // Called via reflection
        private static object CallPropertyGetterByReference<TDeclaringType, TValue>(
            ByRefFunc<TDeclaringType, TValue> getter,
            object target)
        {
            var unboxed = (TDeclaringType)target;
            return getter(ref unboxed);
        }

        // Called via reflection
        private static object CallNullSafePropertyGetter<TDeclaringType, TValue>(
            Func<TDeclaringType, TValue> getter,
            object target)
        {
            if (target == null)
            {
                return null;
            }

            return getter((TDeclaringType)target);
        }

        // Called via reflection
        private static object CallNullSafePropertyGetterByReference<TDeclaringType, TValue>(
            ByRefFunc<TDeclaringType, TValue> getter,
            object target)
        {
            if (target == null)
            {
                return null;
            }

            var unboxed = (TDeclaringType)target;
            return getter(ref unboxed);
        }

        private static void CallPropertySetter<TDeclaringType, TValue>(
            Action<TDeclaringType, TValue> setter,
            object target,
            object value)
        {
            setter((TDeclaringType)target, (TValue)value);
        }

        protected static PropertyHelper[] GetVisibleProperties(
            Type type,
            Func<PropertyInfo, PropertyHelper> createPropertyHelper,
            ConcurrentDictionary<Type, PropertyHelper[]> allPropertiesCache,
            ConcurrentDictionary<Type, PropertyHelper[]> visiblePropertiesCache)
        {
            if (visiblePropertiesCache.TryGetValue(type, out var result))
            {
                return result;
            }

            // The simple and common case, this is normal POCO object - no need to allocate.
            var allPropertiesDefinedOnType = true;
            var allProperties = GetProperties(type, createPropertyHelper, allPropertiesCache);
            foreach (var propertyHelper in allProperties)
            {
                if (propertyHelper.Property.DeclaringType != type)
                {
                    allPropertiesDefinedOnType = false;
                    break;
                }
            }

            if (allPropertiesDefinedOnType)
            {
                result = allProperties;
                visiblePropertiesCache.TryAdd(type, result);
                return result;
            }

            // There's some inherited properties here, so we need to check for hiding via 'new'.
            var filteredProperties = new List<PropertyHelper>(allProperties.Length);
            foreach (var propertyHelper in allProperties)
            {
                var declaringType = propertyHelper.Property.DeclaringType;
                if (declaringType == type)
                {
                    filteredProperties.Add(propertyHelper);
                    continue;
                }

                // If this property was declared on a base type then look for the definition closest to the
                // the type to see if we should include it.
                var ignoreProperty = false;

                // Walk up the hierarchy until we find the type that actually declares this
                // PropertyInfo.
                var currentTypeInfo = type.GetTypeInfo();
                var declaringTypeInfo = declaringType.GetTypeInfo();
                while (currentTypeInfo != null && currentTypeInfo != declaringTypeInfo)
                {
                    // We've found a 'more proximal' public definition
                    var declaredProperty = currentTypeInfo.GetDeclaredProperty(propertyHelper.Name);
                    if (declaredProperty != null)
                    {
                        ignoreProperty = true;
                        break;
                    }

                    currentTypeInfo = currentTypeInfo.BaseType?.GetTypeInfo();
                }

                if (!ignoreProperty)
                {
                    filteredProperties.Add(propertyHelper);
                }
            }

            result = filteredProperties.ToArray();
            visiblePropertiesCache.TryAdd(type, result);
            return result;
        }

        protected static PropertyHelper[] GetProperties(
            Type type,
            Func<PropertyInfo, PropertyHelper> createPropertyHelper,
            ConcurrentDictionary<Type, PropertyHelper[]> cache)
        {
            // Unwrap nullable types. This means Nullable<T>.Value and Nullable<T>.HasValue will not be
            // part of the sequence of properties returned by this method.
            type = Nullable.GetUnderlyingType(type) ?? type;

            if (!cache.TryGetValue(type, out var helpers))
            {
                // We avoid loading indexed properties using the Where statement.
                var properties = type.GetRuntimeProperties().Where(p => IsInterestingProperty(p));

                var typeInfo = type.GetTypeInfo();
                if (typeInfo.IsInterface)
                {
                    // Reflection does not return information about inherited properties on the interface itself.
                    properties = properties.Concat(typeInfo.ImplementedInterfaces.SelectMany(
                        interfaceType => interfaceType.GetRuntimeProperties().Where(p => IsInterestingProperty(p))));
                }

                helpers = properties.Select(p => createPropertyHelper(p)).ToArray();
                cache.TryAdd(type, helpers);
            }

            return helpers;
        }

        private static bool IsInterestingProperty(PropertyInfo property)
        {
            // For improving application startup time, do not use GetIndexParameters() api early in this check as it
            // creates a copy of parameter array and also we would like to check for the presence of a get method
            // and short circuit asap.
            return
                property.GetMethod != null &&
                property.GetMethod.IsPublic &&
                !property.GetMethod.IsStatic &&

                // PropertyHelper can't work with ref structs.
                !IsRefStructProperty(property) &&

                // Indexed properties are not useful (or valid) for grabbing properties off an object.
                property.GetMethod.GetParameters().Length == 0;
        }

        // PropertyHelper can't really interact with ref-struct properties since they can't be 
        // boxed and can't be used as generic types. We just ignore them.
        //
        // see: https://github.com/aspnet/Mvc/issues/8545
        private static bool IsRefStructProperty(PropertyInfo property)
        {
            return
                IsByRefLikeAttribute != null &&
                property.PropertyType.IsValueType &&
                property.PropertyType.IsDefined(IsByRefLikeAttribute);
        }
    }
}
